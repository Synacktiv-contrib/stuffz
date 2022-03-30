// this is a companion script for the presentation "Jailbreak detection mechanisms and how to bypass them" - Pass The Salt 2021 
// slides: https://www.synacktiv.com/sites/default/files/2021-07/Jailbreak_detection-Pass_The_Salt_2021.pdf
// video: https://passthesalt.ubicast.tv/videos/2021-jailbreak-detection-mechanisms-and-how-to-bypass-them/
let blackList = new Set();
blackList.add("/usr/sbin/sshd");
blackList.add("/bin/bash");
blackList.add("/usr/libexec/ssh-keysign");
blackList.add("/private/var/mobile/Library/Caches/kjc.loader");

function iswhite(path) {
    if (blackList.has(path)) return false;
    if (path == null) return true;
    if (path.startsWith('/var/mobile/Containers')) return true;
    if (path.startsWith('/var/containers')) return true;
    if (path.startsWith('/var/mobile/Library')) return true;
    if (path.startsWith('/var/db')) return true;
    if (path.startsWith('/private/var/mobile')) return true;
    if (path.startsWith('/private/var/containers')) return true;
    if (path.startsWith('/private/var/mobile/Library')) return true;
    if (path.startsWith('/private/var/db')) return true;
    if (path.startsWith('/System')) return true;
    if (path.startsWith('/Library/Preferences')) return true;
    if (path.startsWith('/Library/Managed')) return true;
    if (path.startsWith('/usr')) return true;
    if (path.startsWith('/dev')) return true;
    if (path.startsWith('/etc/services')) return true;
    if (path.startsWith('/etc/passwd')) return true;
    if (path.startsWith('/var/log/pspawn_payload_xpcproxy.log')) return true;
    if (path == '/AppleInternal') return true;
    if (path == '/etc/hosts') return true;
    if (path == '/Library') return true;
    if (path == '/var') return true;
    if (path == '/private/var') return true;
    if (path == '/private') return true;
    if (path == '/') return true;
    if (path == '/var/mobile') return true;
    if (path.indexOf('/containers/Bundle/Application') != -1) return true;
    return false;
}

function replaceSyscall(address, size){
    let cpt = 0
    let svc0x80 = "01 10 00 d4"

    Memory.scan(address, size, svc0x80, {
        onMatch(address, size){
            cpt += 1
            Memory.patchCode(address, 4, (address) => {
                let instructionWriter = new Arm64Writer(address);
                instructionWriter.putBrkImm(0);
            });
        },
        onComplete() {
            console.log('[+] Memory.scan() complete found ' + cpt +" svc 0x80");
        }
    })
    
}

let syscall_addr = Memory.alloc(Process.pageSize);
Memory.protect(syscall_addr, Process.pageSize, "r-x");
Memory.patchCode(syscall_addr, Process.pageSize, (addr) => {
    let writer = new Arm64Writer(addr, {pc: syscall_addr});
    writer.putPushRegReg("x6", "x7");
    writer.putInstruction(0xd4001001); // syscall
    writer.putPopRegReg("x6", "x7");
    writer.putBrRegNoAuth("x7");
});

function setProcessExceptionHandler(){
    console.log("setup handler...");
    Process.setExceptionHandler(function (exp) {
        if (exp.type != "breakpoint") {
            console.log(`${Process.enumerateThreads()[0].id} -- Exception ${exp.type} @ ${exp.address} (${exp.address.sub(mainModule.base)})`);
            Thread.sleep(1);
            return false;
        }
        console.log(`syscall svc @ ${exp.address.sub(mainModule.base)}`);
        let syscall_result = syscallHook(exp.context.x16, exp.context.x0, exp.context.x1, exp.context.x2, exp.context.x3, exp.context.x4) || {};
        exp.context.pc = exp.context.pc.add(4)
        if (syscall_result.errno !== undefined) {
            exp.context.x0 = syscall_result.errno;
            exp.context.nzcv |= 1 << 29;
        } else if (syscall_result.retv !== undefined) {
            exp.context.x0 = syscall_result.retv;
            if ((exp.context.nzcv & (1 << 29)) != 0)
                exp.context.nzcv ^= 1 << 29;
        } else {
            // execute the syscall...
            exp.context.r7 = exp.context.pc;
            exp.context.pc = syscall_addr;
        }
        return true;
    });

}

function syscallHook(syscall_num, arg0, arg1, arg2, arg3, arg4) {
    let hook = hooks.find((hook) => hook.syscall === syscall_num.toUInt32());
    if (hook !== undefined)
        return hook.hook(arg0, arg1, arg2, arg3, arg4);
}

let hooks = [
    {
        name: "syscall",
        syscall: 0,
        hook: syscallHook,
        variadic: 1
    }, {
        name: "open",
        syscall: 5,
        hook(arg) {
            let path = arg.readUtf8String()
            if (!iswhite(path)) {
                console.log(`[+] open(${path}) -> NOK`);
                return {errno: 2} // FIXME: fd leak...
            }
            console.log(`[+] open(${path}) -> OK`);
        }
    }, {
        name: "ptrace",
        syscall: 26,
        hook(arg){
            if (arg == 0x1f) { // PT_DENY_ATTACH
                console.log("[+] ptrace(PT_DENY_ATTACH) -> NOK");
                return {retv: 0};
            }
            console.log("[+] ptrace(???) -> OK");
        }
    }, {
        name: "getppid",
        syscall: 39,
        hook(arg){
            console.log("[+] getppid()")
            return {retv: 1}
        }
    }, {
        name: "utimes",
        syscall: 138,
        hook(arg){
            let path = arg.readUtf8String()
            if (!iswhite(path)) {
                console.log(`[+] utimes(${path}) -> NOK`);
                return {errno: 2}
            }
            console.log(`[+] utimes(${path}) -> OK`);
        }
    }, {
        name: "unmount",
        syscall: 159,
        hook(arg){
            console.log("[+] unmount(...)")
            return {errno: 2};
        }
    }, {
        name: "stat",
        syscall: 188,
        hook(arg){
            let path = arg.readUtf8String()
            if (!iswhite(path)) {
                console.log(`[+] stat(${path}) -> NOK`);
                return {errno: 2}
            }
            console.log(`[+] stat(${path}) -> OK`);
        }
    }, {
        name: "pathconf",
        syscall: 191,
        hook(arg){
            let path = arg.readUtf8String()
            if (!iswhite(path)) {
                console.log(`[+] pathconf(${path}) -> NOK`);
                return {errno: 2}
            }
            console.log(`[+] pathconf(${path}) -> OK`);
        }
    }, {
        name: "stat64",
        syscall: 338,
        hook(arg){
            let path = arg.readUtf8String()
            if (!iswhite(path)) {
                console.log(`[+] stat64(${path}) -> NOK`);
                return {errno: 2}
            }
            console.log(`[+] stat64(${path}) -> OK`);
        }
    }, {
        name: "getfsstat64",
        syscall: 347,
        hook(arg){
            console.log("[+] getfsstat64(...)")
            return {errno: 2}
        }
    }, {
        name: "statvfs",
        hook(path, stat) {
            if (path.isNull()) return;
            path = path.readUtf8String();
            if (! path.startsWith("/var")) {
                console.log(`[+] statvfs(${path}) -> patch`);
                return {
                    onLeave() {
                        let f_flag = stat.add(0x30)
                        f_flag.writeU8(f_flag.readU8() | 1)
                    }
                }
            }
            console.log(`[+] statvfs(${path}) -> OK`);
        }
    }, {
        name: "fopen",
        hook(path) {
            if (path.isNull()) return;
            path = path.readUtf8String();
            if (!iswhite(path)) {
                console.log(`[+] fopen(${path}) -> NOK`);
                return {retv: NULL, errno: 13 /* must be != ENOTFOUND */}; // FIXME: FILE* leak...
            }
            console.log(`[+] fopen(${path}) -> OK`);
        }
    }
]

hooks.forEach((hook) => {
    Interceptor.attach(Module.findExportByName(null, hook.name), {
        onEnter: function(args) {
            console.log(`${Process.getCurrentThreadId()}: ${hook.name} func @ ${this.returnAddress.sub(mainModule.base)}`);
            if (hook.variadic !== undefined) {
                let real_args = [];
                for (let i = 0; i < hook.variadic; i++)
                    real_args.push(args[i]);
                for (let i = 0; real_args.length < 5; i++)
                    real_args.push(args[8+i]);
                this.hook_result = hook.hook(...real_args) || {};
            } else {
                this.hook_result = hook.hook(args[0], args[1], args[2], args[3], args[4]) || {};
            }
        }, onLeave: function(retv) {
            if (this.hook_result.errno !== undefined) {
                this.errno = this.hook_result.errno;
                retv.replace(-1);
            }
            if (this.hook_result.retv !== undefined) {
                retv.replace(this.hook_result.retv);
            } 
            if (this.hook_result.onLeave !== undefined) {
                this.hook_result.onLeave();
            }
        }
    })
})

let mainModule = Process.enumerateModules()[0];

console.log("[+] Module base addr: " + mainModule.base)
console.log("[+] Process: " + Process.arch)

setProcessExceptionHandler();
replaceSyscall(mainModule.base, mainModule.size)


if (false) {
    // helper code
    function getRealAddr(target) {
        return mainModule.base.add(ptr(target))
    }


    let strcmps = new Set();
    Interceptor.attach(Module.findExportByName(null, "strncmp"), {
        onEnter: function(args) {
            if (strcmps.has(''+this.returnAddress))
                return;
            if ((this.returnAddress.compare(mainModule.base) >= 0) &&
                (this.returnAddress.compare(mainModule.base.add(mainModule.size)) < 0)) {
                strcmps.add(''+this.returnAddress);
                console.log(`${Process.getCurrentThreadId()}: strncmp(${args[0].readUtf8String()}, ${args[1].readUtf8String()}); // @ ${this.returnAddress.sub(mainModule.base)}`);
            }
        }
    })

    Interceptor.attach(Module.findExportByName(null, "exit"), {
        onEnter: function(args) {
            console.log(`${Process.getCurrentThreadId()}: exit(${args[0].toUInt32()}); // @ ${this.returnAddress.sub(mainModule.base)}`);
        }
    })

    for (let i = 0; i < X_FIXME_X; i+=8) {
        (function (j) {
            Interceptor.attach(getRealAddr(X_FIXME_X).add(i).readPointer(), {
                onEnter: (args) => {
                    console.log("executing InitFunc_"+j/8);
                    Thread.sleep(0.05);
                }, onLeave: (retv) => {
                    console.log("finished executing InitFunc_"+j/8);
                }
            });
        })(i)
    }

    function trace() {
        let tid = Process.getCurrentThreadId();
        console.warn('[+] attaching stalker on thread '+tid);
        Stalker.follow(tid, {
            events: {
                call: false,
                ret: false,
                exec: false,
                block: false,
                compile: true
            },
            transform(iterator) {
                let instruction = iterator.next();

                const startAddress = instruction.address;
                if ((startAddress.compare(mainModule.base) >= 0) &&
                    (startAddress.compare(mainModule.base.add(mainModule.size)) < 0)) {
                    function callback (context) {
                        console.log('executing ' + context.pc.sub(mainModule.base));
                    }
                    iterator.putCallout(callback);
                }
                do {
                    iterator.keep();
                } while ((instruction = iterator.next()) !== null);
            }
        });
    }
}
