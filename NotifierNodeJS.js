const nodeNotifier = require('node-notifier');
const minimist = require('minimist');

// Use dynamic import for 'open'
let openModule;

async function importOpenModule() {
  openModule = await import('open');
}

async function notify(appName, title, content, icon, trigger) {
  nodeNotifier.notify(
    { appName: appName, title: title, message: content, icon: icon, sound: true, wait: true },
    async (error, response, metadata) => {
      if (!error) {
        if ((response === "activate" && metadata.activationType === "clicked") || response === undefined) {
          if (trigger !== "SP:NOTRIGGER") {
            if (!openModule) {
              await importOpenModule();
            }
            await openModule.default(trigger);
          }
        }
      }
    }
  );
}

async function main() {
  const args = minimist(process.argv.slice(2));
  
  if (args['appName'] != undefined && args['title'] != undefined && args['content'] != undefined && args['icon'] != undefined) {
    const trigger = args['trigger'] || "SP:NOTRIGGER";
    await notify(args['appName'], args['title'], args['content'], args['icon'], trigger);
  } else {
    console.error("Invalid arguments.");
    console.error("Usage: programName --appName=appName(string) --title=title(string) --content=content(string) --icon=icon(string: pathToFile / \"undefined\") [--trigger=trigger(string: app/link)]");
  }
}

main().catch(console.error);
