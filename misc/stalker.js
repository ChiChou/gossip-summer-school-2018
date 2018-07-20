Stalker.trustThreshold = 0;

Process.enumerateThreads({
  onComplete: function () {},
  onMatch: function(thread) {
    Stalker.follow(thread.id, {
      events: {
        call: true, // CALL instructions: yes please

        // Other events:
        ret: false, // RET instructions
        exec: false, // all instructions: not recommended as it's
                     //                   a lot of data
        block: false, // block executed: coarse execution trace
        compile: false // block compiled: useful for coverage
      },
      onCallSummary: function (summary) {
        for (var key in summary) {
          const addr = ptr(key);
          if (Process.findModuleByAddress(addr).name === 'JavaScriptCore') {
            console.log(DebugSymbol.fromAddress(addr));
          }
        }
      },
    });
  }
});
