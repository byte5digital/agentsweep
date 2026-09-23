export default async function release({ run }) {
  await run("cargo test --workspace --locked");
}
