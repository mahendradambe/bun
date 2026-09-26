import { Glob } from "bun";
import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import path from "node:path";

// JSC's first VM installs its SIGSEGV/SIGBUS handler without SA_ONSTACK.
// Without that flag the kernel cannot deliver a native stack overflow, and the
// process dies with no crash report. Bun::tryCreateVM (ZigGlobalObject.cpp)
// creates the VM and puts the flag back. A VM created anywhere else can be the
// first one of its process (`bun build --bytecode` never creates a global
// object) and leave the flag off.
test("every JSC::VM is created by Bun::tryCreateVM", async () => {
  const repoRoot = path.resolve(import.meta.dir, "..", "..", "..");
  const createsVM = /\bVM::(?:tryCreate|create|createContextGroup)\s*\(/;
  const sites: string[] = [];
  let scanned = 0;

  for await (const rel of new Glob("**/*.{h,hpp,cpp,cc,mm}").scan({ cwd: path.join(repoRoot, "src") })) {
    scanned++;
    for (const line of readFileSync(path.join(repoRoot, "src", rel), "utf8").split("\n")) {
      if (createsVM.test(line) && !line.trimStart().startsWith("//")) {
        sites.push(`src/${rel.replaceAll("\\", "/")}: ${line.trim()}`);
      }
    }
  }

  // Guard against repoRoot resolving wrong, which would make the check pass vacuously.
  expect(scanned).toBeGreaterThan(0);
  expect(sites).toEqual(["src/jsc/bindings/ZigGlobalObject.cpp: RefPtr<JSC::VM> vm = JSC::VM::tryCreate(heapType);"]);
});
