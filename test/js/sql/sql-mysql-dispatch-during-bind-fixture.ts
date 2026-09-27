// Runs in a subprocess of sql-mysql-dispatch-during-bind.test.ts, against a MySQL server.
// Each scenario named in SCENARIOS gets a pool of one connection and prints one line of JSON.
//
// The "outer" query has a parameter whose conversion runs the code of the scenario. The
// adapter converts a parameter when it writes COM_STMT_EXECUTE:
// - "prepared statement": the connection has the statement and is idle, so the call that
//   starts the query converts.
// - "first execution": the statement is new, so the reply to COM_STMT_PREPARE converts.
import { SQL, randomUUIDv7 } from "bun";
import vm from "node:vm";

type Outcome = { ok: unknown } | { err: string };

// The rows of a query, or the code of its error. An error without a code gives its message.
const outcome = (query: PromiseLike<unknown>): Promise<Outcome> =>
  Promise.resolve(query).then(
    rows => ({ ok: JSON.parse(JSON.stringify(rows)) }),
    error => ({ err: String(error?.code ?? error?.message ?? error) }),
  );

class Scenario {
  conversions = 0;
  reads = 0;
  dispatched: Promise<Outcome>[] = [];
  #connectionId: unknown;

  constructor(
    readonly sql: SQL,
    // Settles when the connection of the pool closes.
    readonly closed: Promise<void>,
  ) {}

  // A query reaches the connection in the call that starts it, which is `execute()`.
  start(query: SQL.Query<any>): Promise<Outcome> {
    return outcome(query.execute());
  }

  // Starts a query from inside a conversion.
  dispatch(query: SQL.Query<any> = this.sql`select 2 as y`) {
    this.dispatched.push(this.start(query));
  }

  // A string parameter. The adapter calls `toString` to convert it, and at no other time.
  text(value: string, convert: () => void = () => {}): String {
    return Object.assign(new String(value), {
      toString: () => {
        this.conversions++;
        convert();
        return value;
      },
    });
  }

  dispatching(count = 1) {
    return this.text("1", () => {
      for (let i = 0; i < count; i++) this.dispatch();
    });
  }

  throws() {
    return this.text("2", () => {
      throw new Error("boom of the started query");
    });
  }

  dispatchesAndThrows(query?: () => SQL.Query<any>) {
    return this.text("1", () => {
      this.dispatch(query?.());
      throw new Error("boom");
    });
  }

  // The conversion never returns: only a termination ends it.
  dispatchesAndSpins(query?: () => SQL.Query<any>) {
    return Object.assign(new String("1"), {
      toString: () => {
        this.dispatch(query?.());
        this.conversions++;
        for (;;) {}
      },
    });
  }

  // Values whose first element is a getter. The adapter reads the values for the signature of
  // the statement, and again to convert them.
  read(onRead: () => void): unknown[] {
    const values: unknown[] = [undefined];
    Object.defineProperty(values, 0, {
      enumerable: true,
      get: () => {
        this.reads++;
        onRead();
        return "1";
      },
    });
    return values;
  }

  // Connects. With `prepare`, the connection also has the statement of the outer query.
  async connect(prepare: boolean) {
    if (prepare) await this.sql`select ${"warm"} as x`;
    const [{ id }] = await this.sql.unsafe("select connection_id() as id").simple();
    this.#connectionId = id;
  }

  async report(outcomes: Record<string, unknown>) {
    const dispatched = await Promise.all(this.dispatched);
    const [{ id }] = await this.sql.unsafe("select connection_id() as id").simple();
    return {
      ...outcomes,
      dispatched,
      conversions: this.conversions,
      // A reply that goes to the wrong request closes the connection, and the pool opens another.
      sameConnection: id === this.#connectionId,
    };
  }

  // Runs `start` inside a call that node:vm terminates. Returns the code of what the call
  // threw. The timeout is long, so that a slow build reaches the conversion before it.
  terminateInsideConversion(start: () => void): string {
    (globalThis as any).startInsideVm = start;
    try {
      vm.runInThisContext("startInsideVm()", { timeout: 1000 });
      return "returned";
    } catch (error: any) {
      return String(error?.code ?? error);
    }
  }

  // Runs `query` and gives what built-in JS gave to its handle: the native connection, which
  // `close()` closes at once, and the function that runs a handle.
  async handleOf(query: any) {
    query.raw(); // creates the handle
    const handle = query[Object.getOwnPropertySymbols(query).find(symbol => symbol.description === "handle")!];
    const run = Object.getPrototypeOf(handle).run;
    let connection: { close(): void } | undefined;
    Object.defineProperty(handle, "run", {
      configurable: true,
      writable: true,
      value(...args: unknown[]) {
        connection = args[0] as { close(): void };
        return run.apply(this, args);
      },
    });
    const settled = await outcome(query);
    return { settled, connection: connection!, runAgain: () => run.call(handle, connection, query) };
  }

  async tableWithOneRow() {
    const table = "dispatch_" + randomUUIDv7("hex").replaceAll("-", "");
    await this.sql.unsafe(`create table ${table} (v varchar(16)) engine=InnoDB`);
    await this.sql.unsafe(`insert into ${table} (v) values ('warm')`);
    return table;
  }

  async reportTable(table: string, outcomes: Record<string, unknown>) {
    const dispatched = await Promise.all(this.dispatched);
    const rows = await outcome(this.sql.unsafe(`select v from ${table} order by v`));
    await this.sql.unsafe(`drop table ${table}`);
    return { ...outcomes, dispatched, rows, conversions: this.conversions };
  }
}

const bothKinds = (scenario: (s: Scenario, prepare: boolean) => Promise<unknown>) =>
  [
    ["prepared statement", true],
    ["first execution", false],
  ].map(([kind, prepare]) => [kind, (s: Scenario) => scenario(s, prepare as boolean)] as const);

const scenarios: Record<string, (s: Scenario) => Promise<unknown>> = {};
const define = (name: string, scenario: (s: Scenario, prepare: boolean) => Promise<unknown>) => {
  for (const [kind, run] of bothKinds(scenario)) scenarios[`${kind}, ${name}`] = run;
};

define("the conversion starts a query", async (s, prepare) => {
  await s.connect(prepare);
  const outer = s.start(s.sql`select ${s.dispatching()} as x`);
  return s.report({ outer: await outer });
});

define("the conversion starts three queries", async (s, prepare) => {
  await s.connect(prepare);
  const outer = s.start(s.sql`select ${s.dispatching(3)} as x`);
  return s.report({ outer: await outer });
});

define("then a query in the same tick", async (s, prepare) => {
  await s.connect(prepare);
  const outer = s.start(s.sql`select ${s.dispatching()} as x`);
  const next = s.start(s.sql`select 3 as z`);
  return s.report({ outer: await outer, next: await next });
});

define("a getter of the values starts a query", async (s, prepare) => {
  await s.connect(prepare);
  const outer = s.start(
    s.sql.unsafe(
      "select ? as x",
      s.read(() => s.dispatch()),
    ),
  );
  return s.report({ outer: await outer, reads: s.reads });
});

define("the started query is a simple query", async (s, prepare) => {
  await s.connect(prepare);
  const simple = () => s.sql.unsafe("select 2 as y").simple();
  const outer = s.start(s.sql`select ${s.text("1", () => s.dispatch(simple()))} as x`);
  return s.report({ outer: await outer });
});

define("the started query has a prepared statement", async (s, prepare) => {
  await s.sql`select 2 as y`;
  await s.connect(prepare);
  const outer = s.start(s.sql`select ${s.dispatching()} as x`);
  return s.report({ outer: await outer });
});

define("the started query shares the statement", async (s, prepare) => {
  await s.connect(prepare);
  const outer = s.start(s.sql`select ${s.text("1", () => s.dispatch(s.sql`select ${"2"} as x`))} as x`);
  return s.report({ outer: await outer });
});

define("the started query starts a query from its conversion", async (s, prepare) => {
  await s.connect(prepare);
  const inner = () => s.sql`select ${s.text("2", () => s.dispatch(s.sql`select 3 as z`))} as x`;
  const outer = s.start(s.sql`select ${s.text("1", () => s.dispatch(inner()))} as x`);
  return s.report({ outer: await outer });
});

define("three queries in one tick, each conversion starts a query", async (s, prepare) => {
  await s.connect(prepare);
  const outers = ["a", "b", "c"].map(value =>
    s.start(s.sql`select ${s.text(value, () => s.dispatch(s.sql`select ${value + value} as y`))} as x`),
  );
  return s.report({ outers: await Promise.all(outers) });
});

define("the conversion throws after it started a query", async (s, prepare) => {
  await s.connect(prepare);
  const outer = s.start(s.sql`select ${s.dispatchesAndThrows()} as x`);
  return s.report({ outer: await outer });
});

define("the conversion throws, then a query in the same tick", async (s, prepare) => {
  await s.connect(prepare);
  const outer = s.start(s.sql`select ${s.dispatchesAndThrows()} as x`);
  const next = s.start(s.sql`select 3 as z`);
  return s.report({ outer: await outer, next: await next });
});

define("the conversion of the started query throws too", async (s, prepare) => {
  await s.connect(prepare);
  const outer = s.start(s.sql`select ${s.dispatchesAndThrows(() => s.sql`select ${s.throws()} as x`)} as x`);
  return s.report({ outer: await outer });
});

scenarios["the conversion runs inside execute()"] = async s => {
  await s.connect(true);
  let returned = false;
  let insideExecute: boolean | undefined;
  const outer = s.start(s.sql`select ${s.text("1", () => void (insideExecute = !returned))} as x`);
  returned = true;
  return s.report({ outer: await outer, insideExecute });
};

scenarios["node:vm timeout stops the conversion after it started a query"] = async s => {
  await s.connect(true);
  const thrown = s.terminateInsideConversion(() => void s.sql`select ${s.dispatchesAndSpins()} as x`.execute());
  const later = await s.start(s.sql`select ${"later"} as t`);
  return s.report({ thrown, later });
};

scenarios["inside a transaction, node:vm timeout stops the conversion after it started an insert"] = async s => {
  await s.connect(true);
  const table = await s.tableWithOneRow();
  const begin = await outcome(
    s.sql.begin(async tx => {
      const insert = () => tx.unsafe(`insert into ${table} (v) values ('nested')`);
      const thrown = s.terminateInsideConversion(() => void tx`select ${s.dispatchesAndSpins(insert)} as x`.execute());
      await Promise.all(s.dispatched);
      throw new Error(thrown);
    }),
  );
  return s.reportTable(table, { begin });
};

scenarios["inside a transaction, the conversion throws after it started an insert"] = async s => {
  await s.connect(true);
  const table = await s.tableWithOneRow();
  const begin = await outcome(
    s.sql.begin(async tx => {
      const insert = () => tx.unsafe(`insert into ${table} (v) values ('nested')`);
      await tx`select ${s.dispatchesAndThrows(insert)} as x`;
    }),
  );
  return s.reportTable(table, { begin });
};

scenarios["inside a savepoint, the conversion throws after it started an insert"] = async s => {
  await s.connect(true);
  const table = await s.tableWithOneRow();
  const begin = await outcome(
    s.sql.begin(async tx => {
      const insert = () => tx.unsafe(`insert into ${table} (v) values ('nested')`);
      return [await outcome(tx.savepoint(sp => sp`select ${s.dispatchesAndThrows(insert)} as x`))];
    }),
  );
  return s.reportTable(table, { begin });
};

// Built-in JS runs a handle one time only.
scenarios["a handle that settled runs again, then the conversion throws after it started a query"] = async s => {
  await s.connect(true);
  const first = await s.handleOf(s.sql`select ${s.throws()} as x`);
  first.runAgain();
  s.conversions = 0;

  const outer = s.start(s.sql`select ${s.dispatchesAndThrows()} as x`);
  return s.report({ first: first.settled, outer: await outer });
};

// After close() the pool of the scenario is of no use: another pool shows that the server
// still answers.
async function afterClose(outcomes: Record<string, unknown>) {
  await using sql = new SQL({ url: process.env.MYSQL_URL, max: 1 });
  return { ...outcomes, afterwards: await outcome(sql`select 1 as ok`) };
}

for (const [kind, prepare] of [
  ["prepared statement", true],
  ["first execution", false],
] as const) {
  scenarios[`close() from a conversion, ${kind}`] = async s => {
    await s.connect(prepare);
    const { connection } = await s.handleOf(s.sql`select 1 as warm`);
    const outer = s.start(s.sql`select ${s.text("1", () => connection.close())} as x`);
    return afterClose({ outer: await outer });
  };
}

scenarios["close() from a conversion, a query waits behind"] = async s => {
  await s.connect(false);
  const { connection } = await s.handleOf(s.sql`select 1 as warm`);
  const outer = s.start(s.sql`select ${s.text("1", () => connection.close())} as x`);
  const behind = s.start(s.sql`select 3 as z`);
  return afterClose({ outer: await outer, behind: await behind });
};

// Both requests fail with nothing sent, so no reply comes for them, and no query follows. The
// requests start in a tick that has no reply. So only their failure can start the idle timer
// of the connection, which closes it.
scenarios["both conversions throw, then the connection is idle"] = async s => {
  await s.connect(true);
  await new Promise(resolve => setImmediate(resolve));
  const outer = s.start(s.sql`select ${s.dispatchesAndThrows(() => s.sql`select ${s.throws()} as x`)} as x`);
  const outcomes = { outer: await outer, dispatched: await Promise.all(s.dispatched) };
  // The interval holds the event loop: an idle connection does not.
  const hold = setInterval(() => {}, 1000);
  await s.closed;
  clearInterval(hold);
  return { ...outcomes, closed: true };
};

for (const name of JSON.parse(process.env.SCENARIOS!) as string[]) {
  const closed = Promise.withResolvers<void>();
  const sql = new SQL({
    url: process.env.MYSQL_URL,
    max: 1,
    idleTimeout: Number(process.env.IDLE_TIMEOUT ?? 0),
    onclose: () => closed.resolve(),
  });
  console.log(JSON.stringify(await scenarios[name](new Scenario(sql, closed.promise))));
}
// A query that a termination stopped never settles, and close() waits for every query.
process.exit(0);
