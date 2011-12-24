// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

#ifndef SRC_NODE_DEBUGGER_H_
#define SRC_NODE_DEBUGGER_H_

#include <node.h>
#include <node_vars.h>
#include <node_object_wrap.h>
#include <node_isolate.h>
#include <v8.h>
#include <v8-debug.h>

#define debug_watcher NODE_VAR(debug_watcher)
#define debug_instance NODE_VAR(debug_instance)

using namespace v8;

namespace node {

class Debug : ObjectWrap {
 public:
  static void Initialize();

  static Handle<Value> New(const Arguments& args);
  static Handle<Value> Enable(const Arguments& args);
  static Handle<Value> Pause(const Arguments& args);
  static Handle<Value> Attach(const Arguments& args);

  static void BreakMessageHandler(const v8::Debug::Message& message) {
    // do nothing with debug messages.
    // The message handler will get changed by DebuggerAgent::CreateSession in
    // debug-agent.cc of v8/src when a new session is created
  }

  static void MessageCallback(uv_async_t* watcher, int status);
  static void MessageDispatch(void);
  static void RegisterDebugSignalHandler(void);

  void Enable(bool wait_connect, unsigned short debug_port);

#ifdef __POSIX__
  // FIXME this is positively unsafe with isolates/threads
  static void EnableDebugSignalHandler(int signal);
#endif // __POSIX__

  // Allocate debugger lazily
  static Debug* GetInstance(void);

  // Allow node.cc starting debugger
  static void SignalBreak(void);

  Debug(v8::Isolate* isolate, node::Isolate* node_isolate)
      : ObjectWrap(),
        isolate_(isolate),
        node_isolate_(node_isolate),
        running_(false) {

    // Set the callback DebugMessageDispatch which is called from the debug
    // thread.
    v8::Debug::SetDebugMessageDispatchHandler(node::Debug::MessageDispatch);

    // Initialize the async watcher. DebugMessageCallback() is called from the
    // main thread to execute a random bit of javascript - which will give V8
    // control so it can handle whatever new message had been received on the
    // debug thread.
    uv_async_init(node_isolate->GetLoop(), &debug_watcher,
                  node::Debug::MessageCallback);

    // unref it so that we exit the event loop despite it being active.
    uv_unref(node_isolate->GetLoop());
  }
  ~Debug() {};

 protected:

  v8::Isolate* isolate_;
  node::Isolate* node_isolate_;
  bool running_;
};

}  // namespace node

#endif  // SRC_NODE_DEBUGGER_H_
