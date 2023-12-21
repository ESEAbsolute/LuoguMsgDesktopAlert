const notifier = require("node-notifier");
const opn = require("opn");

function notify(appName, title, content, icon, trigger) {
  notifier.notify(
    {
      appName: appName,
      title: title,
      message: content,
      icon: icon,
      sound: true,
      wait: true,
    },
    (error, response, metadata) => {
      if (!error) {
        if (response == "activate" && metadata.activationType == "clicked") {
          console.log("clicked");
          if (trigger != "SP:NOTRIGGER") { opn(trigger); }
        } else if (response == undefined) {
          console.log("undifined response -> clicked");
          if (trigger != "SP:NOTRIGGER") { opn(trigger); }
        } else {
          console.log("response:", response);
          console.log("metadata.activationType:", metadata.activationType);
        }
      } else {
        console.error("Notification error:", error);
      }
    }
  );
}
const args = require('minimist')(process.argv.slice(2));
if (
  args['appName'] != undefined &&
  args['title'] != undefined &&
  args['content'] != undefined &&
  args['icon'] != undefined
) {
  if (args['trigger'] == undefined) {
    notify (args['appName'], args['title'], args['content'], args['icon'], "SP:NOTRIGGER");
  } else {
    notify (args['appName'], args['title'], args['content'], args['icon'], args['trigger']);
  }
} else {
  console.error("Invalid arguments.");
  console.error("Usage: programName --appName=appName(string) --title=title(string) --content=content(string) --icon=icon(string: pathToFile / \"undefined\") [--trigger=trigger(string: app/link)]");
}