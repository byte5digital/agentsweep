// Turn one keypress into a letter.
process.stdin.setRawMode(true);
process.stdin.once("data", (buffer) => {
  const key = String.fromCharCode(buffer[0]);
  console.log(key === "y" ? "yes" : "no");
  process.exit(0);
});
