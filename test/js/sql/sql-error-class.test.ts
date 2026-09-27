// The MySQL and PostgreSQL adapters make their errors in native code. Such an
// error is an instance of SQL.MySQLError / SQL.PostgresError on each path to
// the caller:
//   - handle.run() throws it: the query fails before it is sent (a packet that
//     is too large, too many parameters, a failed prepare in the statement cache)
//   - the reject callback gets it: the server answers with an error, or the
//     request queue cannot write the query
//   - the connection callbacks get it: the server refuses the connection
// Errors that have a class of their own (argument validation, TLS) are not
// the subject. A value that user code throws is not the client's error.
import { SQL } from "bun";
import { describe, expect, test } from "bun:test";
import { bunEnv, bunExe, describeWithContainer } from "harness";

type Run = (sql: SQL, query: string, values?: unknown[]) => Promise<unknown>;

const entryPoints: [name: string, run: Run][] = [
  ["sql.unsafe", (sql, query, values) => sql.unsafe(query, values)],
  ["sql.begin", (sql, query, values) => sql.begin(tx => tx.unsafe(query, values))],
  [
    "sql.reserve",
    async (sql, query, values) => {
      const reserved = await sql.reserve();
      try {
        return await reserved.unsafe(query, values);
      } finally {
        reserved.release();
      }
    },
  ],
];

// The failed query must leave the connection as it was.
async function expectUsable(sql: SQL) {
  expect<unknown>(await sql`SELECT 1 AS ok`).toEqual([{ ok: 1 }]);
}

async function rejectionOf(promise: Promise<unknown>): Promise<any> {
  const settled = await promise.then(
    value => ({ resolved: value }),
    reason => ({ rejected: reason }),
  );
  if ("resolved" in settled) throw new Error("expected a rejection, resolved with " + Bun.inspect(settled.resolved));
  return settled.rejected;
}

// expect().resolves runs the event loop until the promise settles, so what
// settles it runs with this function on the stack. While it runs, the events of
// every other test run with this function on the stack too: the tests that use
// it are not concurrent.
function rejectionInsideThisCall(promise: Promise<unknown>): any {
  let rejected: unknown;
  const settled = promise.then(
    () => "resolved",
    reason => {
      rejected = reason;
      return "rejected";
    },
  );
  // A promise that never settles would keep expect().resolves, and with it the
  // whole run, in the event loop for ever.
  const guard = Promise.withResolvers<string>();
  const timer = setTimeout(guard.resolve, 10_000, "not settled");
  try {
    expect(Promise.race([settled, guard.promise])).resolves.toBe("rejected");
  } finally {
    clearTimeout(timer);
  }
  return rejected;
}

// `stack` is the whole stack: the client makes an error while no JavaScript
// runs, or below frames of Bun's own modules, so the error has no frames.
function summary(error: any, Class: { prototype: object }) {
  return {
    prototype: Object.getPrototypeOf(error) === Class.prototype,
    isError: Error.isError(error),
    keys: Object.keys(error),
    name: error.name,
    code: error.code,
    message: error.message,
    stack: error.stack,
  };
}

// An Error that JavaScript makes has these too. They describe the place where
// it was made, which a native error does not have.
const stackKeys = ["stack", "line", "column", "sourceURL", "originalLine", "originalColumn"];
function layout(error: object) {
  return Reflect.ownKeys(error)
    .filter(key => !stackKeys.includes(key as string))
    .map(key => [key, Object.getOwnPropertyDescriptor(error, key)]);
}

class UserError extends Error {}
const thrownValues: [kind: string, value: unknown][] = [
  ["an Error subclass", new UserError("thrown by user code")],
  ["a plain object", { code: "USER_CODE", message: "thrown by user code" }],
  ["a string", "thrown by user code"],
  ["a number", 42],
  ["null", null],
  ["undefined", undefined],
];
// Runs `query` once for each value, on one connection, with a parameter that
// throws the value.
async function arrivals(query: (value: unknown) => Promise<unknown>) {
  const arrived: [kind: string, how: string][] = [];
  for (const [kind, value] of thrownValues) {
    const rejection = await rejectionOf(query(value));
    arrived.push([kind, Object.is(rejection, value) ? "unchanged" : Bun.inspect(rejection)]);
  }
  return arrived;
}
const unchanged = thrownValues.map(([kind]): [kind: string, how: string] => [kind, "unchanged"]);
function throwsOnRead(value: unknown): unknown[] {
  const values: unknown[] = [1];
  Object.defineProperty(values, 0, {
    enumerable: true,
    get() {
      throw value;
    },
  });
  return values;
}
// The first read of the values gives one parameter, each later read gives two.
function growsAfterTheFirstRead(): unknown[] {
  const values: unknown[] = [1];
  let reads = 0;
  Object.defineProperty(values, 0, {
    enumerable: true,
    configurable: true,
    get() {
      if (reads++ === 0) values.push(2);
      return 1;
    },
  });
  return values;
}

// One byte more than a single MySQL packet can frame, with the command byte.
const oversizedQuery = () => Buffer.alloc(0xffffff, "-").toString();
const oversizedParameter = () => Buffer.alloc(0xffffff);
// The PostgreSQL wire protocol counts the parameters of a statement in 16 bits.
const tooManyParameters = () => new Array(65536).fill(null);
const tooManyParametersMessage =
  "query has too many parameters - the PostgreSQL wire protocol supports a maximum of 65535 parameters per query. Try reducing your batch size.";

describeWithContainer("mysql", { image: "mysql_plain", concurrent: true }, container => {
  const url = () => `mysql://root@${container.host}:${container.port}/bun_sql_test`;
  const overflow = (message: string) => ({
    prototype: true,
    isError: true,
    keys: ["name", "code"],
    name: "MySQLError",
    code: "ERR_MYSQL_OVERFLOW",
    message,
    stack: "MySQLError: " + message,
  });

  describe.each(entryPoints)("%s", (_, run) => {
    test("a COM_QUERY that is too large rejects with a MySQLError", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      await sql`SELECT 1`;

      const error = await rejectionOf(run(sql, oversizedQuery()));
      expect(summary(error, SQL.MySQLError)).toEqual(overflow("failed to execute query"));
      await expectUsable(sql);
    });

    test("a COM_STMT_PREPARE that is too large rejects with a MySQLError", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      await sql`SELECT 1`;

      const error = await rejectionOf(run(sql, oversizedQuery(), [1]));
      expect(summary(error, SQL.MySQLError)).toEqual(overflow("failed to prepare query"));
      await expectUsable(sql);
    });

    test("a COM_STMT_EXECUTE that is too large rejects with a MySQLError", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      // The statement is prepared, so the next use writes the execute at once.
      expect(await run(sql, "SELECT length(?) AS n", [Buffer.alloc(1)])).toEqual([{ n: 1 }]);

      const error = await rejectionOf(run(sql, "SELECT length(?) AS n", [oversizedParameter()]));
      expect(summary(error, SQL.MySQLError)).toEqual(overflow("failed to bind and execute query"));
      await expectUsable(sql);
    });

    test("a COM_STMT_EXECUTE that is too large for a new statement rejects with a MySQLError", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      await sql`SELECT 1`;

      // The statement is not prepared, so the request queue writes the execute
      // when the server has answered the prepare.
      const error = await rejectionOf(run(sql, "SELECT length(?) AS n", [oversizedParameter()]));
      expect(summary(error, SQL.MySQLError)).toEqual(overflow("failed to bind and execute query"));
      await expectUsable(sql);
    });

    test("a wrong number of parameters for a prepared statement rejects with a MySQLError", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      expect(await run(sql, "SELECT ? AS n", [1])).toEqual([{ n: 1 }]);

      const error = await rejectionOf(run(sql, "SELECT ? AS n", growsAfterTheFirstRead()));
      expect(summary(error, SQL.MySQLError)).toEqual({
        prototype: true,
        isError: true,
        keys: ["name", "code"],
        name: "MySQLError",
        code: "ERR_MYSQL_WRONG_NUMBER_OF_PARAMETERS_PROVIDED",
        message: "failed to bind and execute query",
        stack: "MySQLError: failed to bind and execute query",
      });
      await expectUsable(sql);
    });

    test("each run of a statement that fails to prepare rejects with the same MySQLError", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });

      const errors: any[] = [];
      for (let i = 0; i < 3; i++) {
        errors.push(await rejectionOf(run(sql, "SELECT * FROM no_such_table_for_error_class WHERE a = ?", [1])));
      }
      const expected = {
        prototype: true,
        isError: true,
        keys: ["name", "code", "errno", "sqlState"],
        name: "MySQLError",
        code: "ERR_MYSQL_SERVER_ERROR",
        message: "Table 'bun_sql_test.no_such_table_for_error_class' doesn't exist",
        stack: "MySQLError: Table 'bun_sql_test.no_such_table_for_error_class' doesn't exist",
      };
      expect(errors.map(error => summary(error, SQL.MySQLError))).toEqual([expected, expected, expected]);
      expect(errors.map(error => [error.errno, error.sqlState])).toEqual([
        [1146, "42S02"],
        [1146, "42S02"],
        [1146, "42S02"],
      ]);
    });

    test("a value thrown while the parameters are read arrives unchanged", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      await sql`SELECT 1`;

      expect(await arrivals(value => run(sql, "SELECT ? AS a", throwsOnRead(value)))).toEqual(unchanged);
      await expectUsable(sql);
    });
  });

  test("an error that the server sends while the client connects is a MySQLError", async () => {
    await container.ready;
    await using sql = new SQL({
      url: `mysql://root@${container.host}:${container.port}/no_such_database_for_error_class`,
      max: 1,
    });

    const error = await rejectionOf(sql`SELECT 1`);
    expect(summary(error, SQL.MySQLError)).toEqual({
      prototype: true,
      isError: true,
      keys: ["name", "code", "errno", "sqlState"],
      name: "MySQLError",
      code: "ERR_MYSQL_SERVER_ERROR",
      message: "Unknown database 'no_such_database_for_error_class'",
      stack: "MySQLError: Unknown database 'no_such_database_for_error_class'",
    });
    expect([error.errno, error.sqlState]).toEqual([1049, "42000"]);
  });

  test("a native error has the layout of new SQL.MySQLError()", async () => {
    await container.ready;
    await using sql = new SQL({ url: url(), max: 1 });
    await sql`SELECT 1`;

    const thrown = await rejectionOf(sql.unsafe(oversizedQuery()));
    const fromServer = await rejectionOf(sql`SELECT * FROM no_such_table_for_error_class`);
    for (const error of [thrown, fromServer]) {
      const { code, errno, sqlState } = error;
      const reference = new SQL.MySQLError(error.message, { code, errno, sqlState });
      expect(layout(error)).toEqual(layout(reference));
      expect(String(error)).toBe(String(reference));
      expect(error).toBeInstanceOf(SQL.SQLError);
      expect(error).toBeInstanceOf(Error);
      expect(Object.prototype.toString.call(error)).toBe("[object Error]");
    }
    expect(layout(fromServer).map(([key]) => key)).toEqual(["message", "name", "code", "errno", "sqlState"]);
  });
});

describeWithContainer("postgres", { image: "postgres_plain", concurrent: true }, container => {
  const url = () => `postgres://bun_sql_test@${container.host}:${container.port}/bun_sql_test`;
  const tooMany = {
    prototype: true,
    isError: true,
    keys: ["name", "code", "hint"],
    name: "PostgresError",
    code: "ERR_POSTGRES_TOO_MANY_PARAMETERS",
    message: tooManyParametersMessage,
    stack: "PostgresError: " + tooManyParametersMessage,
  };

  describe.each(entryPoints)("%s", (_, run) => {
    test("a query with too many parameters rejects with a PostgresError", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      await sql`SELECT 1`;

      const error = await rejectionOf(run(sql, "SELECT 1", tooManyParameters()));
      expect(summary(error, SQL.PostgresError)).toEqual(tooMany);
      await expectUsable(sql);
    });

    test("a value thrown while the parameters are read arrives unchanged", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      await sql`SELECT 1`;

      expect(await arrivals(value => run(sql, "SELECT $1::int AS a", throwsOnRead(value)))).toEqual(unchanged);
      await expectUsable(sql);
    });
  });

  test("each run of a statement that the client cannot write rejects with the same PostgresError", async () => {
    await container.ready;
    await using sql = new SQL({ url: url(), max: 1 });
    await sql`SELECT 1`;

    // A query is running, so the next one waits in the queue, and the queue
    // cannot write it. Its statement stays in the cache as failed.
    const running = sql`SELECT 1 AS a`.execute();
    const queued = sql.unsafe("SELECT 1 AS cached", tooManyParameters()).execute();
    const errors = [await rejectionOf(queued)];
    expect<unknown>(await running).toEqual([{ a: 1 }]);
    for (let i = 0; i < 2; i++) errors.push(await rejectionOf(sql.unsafe("SELECT 1 AS cached", tooManyParameters())));

    expect(errors.map(error => summary(error, SQL.PostgresError))).toEqual([tooMany, tooMany, tooMany]);
    await expectUsable(sql);
  });

  test("an error that the server sends while the client connects is a PostgresError", async () => {
    await container.ready;
    await using sql = new SQL({
      url: `postgres://bun_sql_test@${container.host}:${container.port}/no_such_database_for_error_class`,
      max: 1,
    });

    const error = await rejectionOf(sql`SELECT 1`);
    expect(summary(error, SQL.PostgresError)).toEqual({
      prototype: true,
      isError: true,
      keys: ["name", "code", "errno", "severity", "file", "routine"],
      name: "PostgresError",
      code: "ERR_POSTGRES_SERVER_ERROR",
      message: 'database "no_such_database_for_error_class" does not exist',
      stack: 'PostgresError: database "no_such_database_for_error_class" does not exist',
    });
    expect([error.errno, error.severity]).toEqual(["3D000", "FATAL"]);
  });

  test("a native error has the layout of new SQL.PostgresError()", async () => {
    await container.ready;
    await using sql = new SQL({ url: url(), max: 1 });
    await sql`SELECT 1`;

    const thrown = await rejectionOf(sql.unsafe("SELECT 1", tooManyParameters()));
    const fromServer = await rejectionOf(sql`SELECT * FROM no_such_table_for_error_class`);
    // The server can send an empty message.
    const noMessage = await rejectionOf(sql.unsafe(`DO $$ BEGIN RAISE EXCEPTION USING MESSAGE = ''; END $$`));
    for (const error of [thrown, fromServer, noMessage]) {
      const reference = new SQL.PostgresError(error.message, { ...error, line: error.line, column: error.column });
      expect(layout(error)).toEqual(layout(reference));
      expect(String(error)).toBe(String(reference));
      expect(error).toBeInstanceOf(SQL.SQLError);
      expect(error).toBeInstanceOf(Error);
      expect(Object.prototype.toString.call(error)).toBe("[object Error]");
    }
    expect(summary(fromServer, SQL.PostgresError)).toEqual({
      prototype: true,
      isError: true,
      keys: ["name", "code", "errno", "severity", "position", "file", "routine"],
      name: "PostgresError",
      code: "ERR_POSTGRES_SERVER_ERROR",
      message: 'relation "no_such_table_for_error_class" does not exist',
      stack: 'PostgresError: relation "no_such_table_for_error_class" does not exist',
    });
    expect({ message: noMessage.message, stack: noMessage.stack, errno: noMessage.errno }).toEqual({
      message: "",
      stack: "PostgresError",
      errno: "P0001",
    });
  });
});

// Runs `body` with an Error.prepareStackTrace that reports each error of the
// adapter that it is asked to format. These tests are not concurrent: the
// function is global.
async function withPrepareStackTrace<T>(onError: (error: Error) => void, body: () => T | Promise<T>): Promise<T> {
  const original = Error.prepareStackTrace;
  Error.prepareStackTrace = (error, frames) => {
    if (error instanceof SQL.SQLError) onError(error);
    return String(error) + frames.map(frame => "\n    at " + frame).join("");
  };
  try {
    return await body();
  } finally {
    Error.prepareStackTrace = original;
  }
}

// The same error in the three states of the JavaScript stack that a native
// error can be made in.
const madeWith: [state: string, make: (query: SQL.Query<any>) => Promise<any> | any][] = [
  ["no JavaScript on the stack", query => rejectionOf(query)],
  [
    "the caller of execute() on the stack",
    query => {
      // execute() calls handle.run() before it returns.
      query.execute();
      return rejectionOf(query);
    },
  ],
  ["the function that runs the event loop on the stack", query => rejectionInsideThisCall(query)],
];

describeWithContainer("mysql: the stack of a native error", { image: "mysql_plain" }, container => {
  const url = () => `mysql://root@${container.host}:${container.port}/bun_sql_test`;

  describe.each(madeWith)("made with %s", (_, make) => {
    test("is the name and the message, and Error.prepareStackTrace does not run", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      await sql`SELECT 1`;

      const formatted: unknown[] = [];
      const [thrown, fromServer] = await withPrepareStackTrace(
        error => formatted.push(error),
        async () => [
          await make(sql.unsafe(oversizedQuery())),
          await make(sql.unsafe("SELECT * FROM no_such_table_for_error_class")),
        ],
      );
      expect({ thrown: thrown.stack, fromServer: fromServer.stack, formatted }).toEqual({
        thrown: "MySQLError: failed to execute query",
        fromServer: "MySQLError: Table 'bun_sql_test.no_such_table_for_error_class' doesn't exist",
        formatted: [],
      });
    });
  });
});

describeWithContainer("postgres: the stack of a native error", { image: "postgres_plain" }, container => {
  const url = () => `postgres://bun_sql_test@${container.host}:${container.port}/bun_sql_test`;
  const message = `null value in column "id" of relation "error_class_not_null" violates not-null constraint`;

  // An Error has a `line` and a `column` of its own: the position in the source
  // where it was made. JSC writes them when it fills the stack. PostgreSQL has
  // fields with the same names, and they must stay the server's.
  const fields = (error: any) => ({
    prototype: Object.getPrototypeOf(error) === SQL.PostgresError.prototype,
    code: error.code,
    errno: error.errno,
    table: error.table,
    column: Object.getOwnPropertyDescriptor(error, "column"),
    line: {
      ...Object.getOwnPropertyDescriptor(error, "line"),
      value: /^[0-9]+$/.test(error.line) ? "digits" : error.line,
    },
  });
  const serverFields = {
    prototype: true,
    code: "ERR_POSTGRES_SERVER_ERROR",
    errno: "23502",
    table: "error_class_not_null",
    column: { value: "id", writable: true, enumerable: false, configurable: true },
    line: { value: "digits", writable: true, enumerable: false, configurable: true },
  };

  describe.each(madeWith)("made with %s", (_, make) => {
    test("is the name and the message, and Error.prepareStackTrace does not run", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      await sql`CREATE TEMPORARY TABLE error_class_not_null (id int NOT NULL)`;

      const formatted: unknown[] = [];
      const [thrown, fromServer] = await withPrepareStackTrace(
        error => formatted.push(error),
        async () => [
          await make(sql.unsafe("SELECT 1", tooManyParameters())),
          await make(sql`INSERT INTO error_class_not_null (id) VALUES (${null})`),
        ],
      );
      expect({ thrown: thrown.stack, fromServer: fromServer.stack, formatted }).toEqual({
        thrown: "PostgresError: " + tooManyParametersMessage,
        fromServer: "PostgresError: " + message,
        formatted: [],
      });
      expect(fields(fromServer)).toEqual(serverFields);
    });

    test("keeps the server's line and column when the stack is filled again", async () => {
      await container.ready;
      await using sql = new SQL({ url: url(), max: 1 });
      await sql`CREATE TEMPORARY TABLE error_class_not_null (id int NOT NULL)`;

      const error = await make(sql`INSERT INTO error_class_not_null (id) VALUES (${null})`);
      Bun.gc(true);
      expect(fields(error)).toEqual(serverFields);

      (function capturesTheStack() {
        Error.captureStackTrace(error);
      })();
      expect(error.stack).toStartWith("PostgresError: " + message + "\n");
      expect(error.stack).toContain("capturesTheStack");
      expect(fields(error)).toEqual(serverFields);
    });
  });

  test("keeps the server's line and column when a stream reports the error", async () => {
    await container.ready;
    await using sql = new SQL({ url: url(), max: 1 });
    await sql`CREATE TEMPORARY TABLE error_class_not_null (id int NOT NULL)`;

    // A stream gives the stack of its reader to an error that has no stack yet.
    const stream = new ReadableStream({
      async pull(controller) {
        try {
          await sql`INSERT INTO error_class_not_null (id) VALUES (${null})`;
          controller.close();
        } catch (error) {
          controller.error(error);
        }
      },
    });
    const error = await (async function readsTheStream() {
      return await rejectionOf(stream.getReader().read());
    })();
    expect(fields(error)).toEqual(serverFields);
    expect(error.stack).toBe("PostgresError: " + message);
  });

  test("an Error.prepareStackTrace that throws does not keep the query pending", async () => {
    await container.ready;
    await using sql = new SQL({ url: url(), max: 1 });
    await sql`CREATE TEMPORARY TABLE error_class_not_null (id int NOT NULL)`;

    const error = await withPrepareStackTrace(
      () => {
        throw new UserError("thrown by Error.prepareStackTrace");
      },
      () => rejectionOf(sql`INSERT INTO error_class_not_null (id) VALUES (${null})`),
    );
    expect(fields(error)).toEqual(serverFields);
    await expectUsable(sql);
  });
});

// Process-wide state that user code can change. The fixture changes it, so it
// needs a process of its own.
describe("with Object.prototype, Error.prototype.name and Error.prepareStackTrace changed", () => {
  const fixture = /* js */ `
    const { SQL } = require("bun");
    const { ADAPTER: adapter, DATABASE_URL: url } = process.env;
    const Class = adapter === "mysql" ? SQL.MySQLError : SQL.PostgresError;
    const sql = new SQL({ url, max: 1 });
    await sql\`SELECT 1\`;

    const userCode = [];
    for (const key of ["errno", "sqlState", "detail", "hint", "severity", "routine", "line", "column"]) {
      Object.prototype[key] = "from Object.prototype";
    }
    Object.defineProperty(Error.prototype, "name", {
      configurable: true,
      get() {
        return "Error";
      },
      set() {
        userCode.push("Error.prototype.name setter");
      },
    });
    Error.prepareStackTrace = (error, frames) => {
      userCode.push("Error.prepareStackTrace");
      return String(error) + frames.map(frame => "\\n    at " + frame).join("");
    };

    const queries = {
      thrown:
        adapter === "mysql"
          ? sql.unsafe(Buffer.alloc(0xffffff, "-").toString())
          : sql.unsafe("SELECT 1", new Array(65536).fill(null)),
      fromServer: sql\`SELECT * FROM no_such_table_for_error_class\`,
    };
    const result = {};
    for (const [path, query] of Object.entries(queries)) {
      const error = await query.then(() => "resolved", error => error);
      result[path] = {
        prototype: Object.getPrototypeOf(error) === Class.prototype,
        keys: Object.keys(error),
        name: error.name,
        // What ran before the caller had the error ran inside the client.
        userCode: userCode.splice(0),
      };
    }
    await sql.close();
    console.log(JSON.stringify(result));
  `;

  for (const [adapter, image, name, url, keys] of [
    [
      "mysql",
      "mysql_plain",
      "MySQLError",
      (host: string, port: number) => `mysql://root@${host}:${port}/bun_sql_test`,
      { thrown: ["name", "code"], fromServer: ["name", "code", "errno", "sqlState"] },
    ],
    [
      "postgres",
      "postgres_plain",
      "PostgresError",
      (host: string, port: number) => `postgres://bun_sql_test@${host}:${port}/bun_sql_test`,
      {
        thrown: ["name", "code", "hint"],
        fromServer: ["name", "code", "errno", "severity", "position", "file", "routine"],
      },
    ],
  ] as const) {
    describeWithContainer(adapter, { image }, container => {
      test("a native error is an instance of the class and no user code runs inside the client", async () => {
        await container.ready;
        await using proc = Bun.spawn({
          cmd: [bunExe(), "-e", fixture],
          env: { ...bunEnv, ADAPTER: adapter, DATABASE_URL: url(container.host, container.port) },
          stdout: "pipe",
          stderr: "pipe",
        });
        const [stdout, stderr, exitCode] = await Promise.all([proc.stdout.text(), proc.stderr.text(), proc.exited]);
        // stderr is here so that a failure shows it. A sanitizer build can write to it.
        expect({ stdout: stdout.trim() && JSON.parse(stdout), stderr, exitCode }).toEqual({
          stdout: {
            thrown: { prototype: true, keys: keys.thrown, name, userCode: [] },
            fromServer: { prototype: true, keys: keys.fromServer, name, userCode: [] },
          },
          stderr: expect.any(String),
          exitCode: 0,
        });
      });
    });
  }
});
