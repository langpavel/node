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

#include <node.h>
#include <node_debugger.h>
#include <node_vars.h>
#include <node_version.h>
#include <v8.h>
#include <v8-debug.h>

#include <errno.h>
#include <assert.h>

#define process NODE_VAR(process)
#define debug_instance NODE_VAR(debug_instance)

#define UNWRAP Debug *d = ObjectWrap::Unwrap<Debug>(args.Holder())

using namespace v8;

namespace node {

static Debug* main_debugger_ = NULL;

void Debug::Initialize() {
  HandleScope scope;

  Local<FunctionTemplate> t = FunctionTemplate::New(Debug::New);
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("Debugger"));

  NODE_SET_PROTOTYPE_METHOD(t, "enable", Debug::Enable);
  NODE_SET_PROTOTYPE_METHOD(t, "pause", Debug::Pause);
  NODE_SET_PROTOTYPE_METHOD(t, "attach", Debug::Attach);

  Handle<Value> argv[0];
  Handle<Object> debug_instance_ = t->GetFunction()->NewInstance(0, argv);

  process->Set(String::NewSymbol("_debugger"), debug_instance_);
  debug_instance = Persistent<Object>::New(debug_instance_);
}


Handle<Value> Debug::New(const Arguments& args) {
  HandleScope scope;
  Debug *p = new node::Debug(v8::Isolate::GetCurrent(),
                             node::Isolate::GetCurrent());
  p->Wrap(args.Holder());
  return args.This();
}


Handle<Value> Debug::Enable(const Arguments& args) {
  HandleScope scope;

  if (args.Length() < 2) {
    return ThrowException(Exception::Error(String::New(
        "Debug::Enable takes two arguments: [wait_connect], [port]"
    )));
  }

  UNWRAP;

  bool wait_connect = args[0]->ToBoolean()->Value();
  unsigned short debug_port = args[1]->ToNumber()->Value();

  d->Enable(wait_connect, debug_port);

  return Undefined();
}


void Debug::Enable(bool wait_connect, unsigned short debug_port) {
  // If we're called from another thread, make sure to enter the right
  // v8 isolate.
  isolate_->Enter();

  if (wait_connect) {
    // Set up an empty handler so v8 will not continue until a debugger
    // attaches. This is the same behavior as Debug::EnableAgent(_,_,true)
    // except we don't break at the beginning of the script.
    // see Debugger::StartAgent in debug.cc of v8/src
    v8::Debug::SetMessageHandler2(node::Debug::BreakMessageHandler);
  }

  // Start the debug thread
  if (debug_port != 0) {
    // and it's associated TCP server on port 5858.
    v8::Debug::EnableAgent("node " NODE_VERSION, debug_port);

    // Print out some information.
    fprintf(stderr, "debugger listening on port %d\n", debug_port);
    fflush(stderr);
  } else {
    // Break current isolate as it won't broke automatically
    v8::Debug::DebugBreak(isolate_);
  }

  running_ = true;

  isolate_->Exit();
}


Handle<Value> Debug::Pause(const Arguments& args) {
  HandleScope scope;

  UNWRAP;

  v8::Debug::DebugBreak(d->isolate_);
  return Undefined();
}


void Debug::SignalBreak(void) {
  if (!main_debugger_->running_) {
#ifdef __POSIX__
    v8::Debug::DebugBreak(main_debugger_->isolate_);
    fprintf(stderr, "Hit SIGUSR1 - starting debugger agent.\n");
    main_debugger_->Enable(false, 5858);
#endif // __POSIX__
#ifdef _WIN32
    for (int i = 0; i < 1; i++) {
      fprintf(stderr, "Starting debugger agent.\r\n");
      fflush(stderr);
      main_debugger_->Enable(false, 5858);
    }
    v8::Debug::DebugBreak(main_debugger_->isolate_);
#endif // _WIN32
  }
}


Debug* Debug::GetInstance(void) {
  // Lazily initialize debugger and insert correct _debugger
  // property into `process` variable
  if (debug_instance.IsEmpty()) {
    Debug::Initialize();
  }

  return ObjectWrap::Unwrap<Debug>(debug_instance);
}


// Platform specific Attach() implementation

#ifdef __POSIX__
int Debug::RegisterDebugSignalHandler(void) {
  if (main_debugger_ != NULL) return -1;
  main_debugger_ = Debug::GetInstance();
  // node.cc will register actual handler
  return 0;
}

// FIXME this is positively unsafe with isolates/threads
void Debug::EnableDebugSignalHandler(int signal) {
  Debug::SignalBreak();
}


Handle<Value> Debug::Attach(const Arguments& args) {
  HandleScope scope;

  if (args.Length() != 1) {
    return ThrowException(Exception::Error(
        String::New("Invalid number of arguments.")));
  }

  pid_t pid;
  int r;

  pid = args[0]->IntegerValue();
  r = kill(pid, SIGUSR1);
  if (r != 0) {
    return ThrowException(ErrnoException(errno, "kill"));
  }

  return Undefined();
}
#endif // __POSIX__


#ifdef _WIN32
int Debug::RegisterDebugSignalHandler(void) {
  if (main_debugger_ != NULL) return -1;

  char mapping_name[32];
  HANDLE mapping_handle;
  DWORD pid;
  LPTHREAD_START_ROUTINE* handler;

  pid = GetCurrentProcessId();

  if (GetDebugSignalHandlerMappingName(pid,
                                       mapping_name,
                                       sizeof mapping_name) < 0) {
    return -1;
  }

  mapping_handle = CreateFileMappingA(INVALID_HANDLE_VALUE,
                                      NULL,
                                      PAGE_READWRITE,
                                      0,
                                      sizeof *handler,
                                      mapping_name);
  if (mapping_handle == NULL) {
    return -1;
  }

  handler = (LPTHREAD_START_ROUTINE*) MapViewOfFile(mapping_handle,
                                                    FILE_MAP_ALL_ACCESS,
                                                    0,
                                                    0,
                                                    sizeof *handler);
  if (handler == NULL) {
    CloseHandle(mapping_handle);
    return -1;
  }

  main_debugger_ = Debug::GetInstance();

  *handler = EnableDebugThreadProc;

  UnmapViewOfFile((void*) handler);

  return 0;
}


DWORD WINAPI EnableDebugThreadProc(void* arg) {
  Debug::SignalBreak();
  return 0;
}


static int GetDebugSignalHandlerMappingName(DWORD pid, char* buf, size_t buf_len) {
  return snprintf(buf, buf_len, "node-debug-handler-%u", pid);
}


Handle<Value> Debug::Attach(const Arguments& args) {
  HandleScope scope;
  Handle<Value> rv = Undefined();
  DWORD pid;
  HANDLE process_l = NULL;
  HANDLE thread = NULL;
  HANDLE mapping = NULL;
  char mapping_name[32];
  LPTHREAD_START_ROUTINE* handler = NULL;

  if (args.Length() != 1) {
    rv = ThrowException(Exception::Error(String::New(
        "Invalid number of arguments."
    )));
    goto out;
  }

  pid = (DWORD) args[0]->IntegerValue();

  process_l = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                            PROCESS_VM_READ,
                          FALSE,
                          pid);
  if (process_l == NULL) {
    rv = ThrowException(WinapiErrnoException(GetLastError(), "OpenProcess"));
    goto out;
  }

  if (GetDebugSignalHandlerMappingName(pid,
                                       mapping_name,
                                       sizeof mapping_name) < 0) {
    rv = ThrowException(ErrnoException(errno, "sprintf"));
    goto out;
  }

  mapping = OpenFileMapping(FILE_MAP_READ, FALSE, mapping_name);
  if (mapping == NULL) {
    rv = ThrowException(WinapiErrnoException(GetLastError(), "sprintf"));
    goto out;
  }

  handler = (LPTHREAD_START_ROUTINE*) MapViewOfFile(mapping,
                                                    FILE_MAP_READ,
                                                    0,
                                                    0,
                                                    sizeof *handler);
  if (handler == NULL || *handler == NULL) {
    rv = ThrowException(WinapiErrnoException(GetLastError(), "MapViewOfFile"));
    goto out;
  }

  thread = CreateRemoteThread(process_l,
                              NULL,
                              0,
                              *handler,
                              NULL,
                              0,
                              NULL);
  if (thread == NULL) {
    rv = ThrowException(WinapiErrnoException(GetLastError(),
                                             "CreateRemoteThread"));
    goto out;
  }

  // Wait for the thread to terminate
  if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0) {
    rv = ThrowException(WinapiErrnoException(GetLastError(),
                                             "WaitForSingleObject"));
    goto out;
  }

 out:
  if (process_l != NULL) {
   CloseHandle(process_l);
  }
  if (thread != NULL) {
    CloseHandle(thread);
  }
  if (handler != NULL) {
    UnmapViewOfFile(handler);
  }
  if (mapping != NULL) {
    CloseHandle(mapping);
  }

  return Undefined();
}
#endif // _WIN32

} // namespace node
