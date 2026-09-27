#include "root.h"

#include <JavaScriptCore/ErrorInstance.h>
#include <JavaScriptCore/ErrorInstanceInlines.h>
#include <JavaScriptCore/JSCInlines.h>
#include <wtf/text/MakeString.h>
#include "helpers.h"

namespace Bun {

using namespace JSC;

// `prototype` is `MySQLError.prototype` or `PostgresError.prototype` (src/js/internal/sql/errors.ts).
extern "C" [[ZIG_EXPORT(nothrow)]] JSC::EncodedJSValue Bun__SQLError__createStructure(JSC::JSGlobalObject* globalObject, JSC::EncodedJSValue encodedPrototype)
{
    JSValue prototype = JSValue::decode(encodedPrototype);
    if (!prototype.isObject())
        return {};
    return JSValue::encode(ErrorInstance::createStructure(globalObject->vm(), globalObject, prototype));
}

// An error of the class that `encodedStructure` was made for, built with no call into JS.
//
// The client makes an error while no JavaScript runs, or below frames of Bun's own modules, so the
// error keeps no stack frames and `stack` is "<name>: <message>". The error info is materialized
// here: JSC writes `stack`, `line` and `column` of an error once, on the first read of one of them,
// and PostgreSQL has fields named `line` and `column`. After this call nothing writes them again
// and there is nothing left that Error.prepareStackTrace could format.
extern "C" [[ZIG_EXPORT(zero_is_throw)]] JSC::EncodedJSValue Bun__SQLError__create(JSC::JSGlobalObject* globalObject, JSC::EncodedJSValue encodedStructure, bool isMySQL, const char* messagePtr, size_t messageLength)
{
    auto& vm = getVM(globalObject);
    auto scope = DECLARE_THROW_SCOPE(vm);

    ASCIILiteral name = isMySQL ? "MySQLError"_s : "PostgresError"_s;
    String message = messageLength
        ? Zig::convertUTF8ToString(std::span { reinterpret_cast<const unsigned char*>(messagePtr), messageLength })
        : emptyString();
    String stack = message.isEmpty() ? String(name) : tryMakeString(name, ": "_s, message);
    if (message.isNull() || stack.isNull()) [[unlikely]] {
        throwOutOfMemoryError(globalObject, scope);
        return {};
    }

    // Without a registered class the value is still an Error with the same own properties.
    JSValue registered = JSValue::decode(encodedStructure);
    auto* structure = registered ? dynamicDowncast<Structure>(registered) : nullptr;
    if (!structure)
        structure = globalObject->errorStructure();

    auto* error = ErrorInstance::create(vm, structure, message, JSValue());
    error->setErrorInfoForEmbedderError({}, {}, WTF::move(stack));
    error->materializeErrorInfoIfNeeded(vm);
    // The position of no source. The caller writes the server's `line` and `column`, if any.
    error->putDirect(vm, vm.propertyNames->line, jsUndefined(), static_cast<unsigned>(PropertyAttribute::DontEnum));
    error->putDirect(vm, vm.propertyNames->column, jsUndefined(), static_cast<unsigned>(PropertyAttribute::DontEnum));
    // Own and enumerable, as `this.name = ...` in the constructor of the class makes it.
    error->putDirect(vm, vm.propertyNames->name, jsNontrivialString(vm, name), 0);
    return JSValue::encode(error);
}

}
