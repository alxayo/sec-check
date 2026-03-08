// @ts-check
import * as esbuild from "esbuild";

const production = process.argv.includes("--production");
const watch = process.argv.includes("--watch");

/** @type {import('esbuild').BuildOptions} */
const extensionConfig = {
  entryPoints: ["src/extension.ts"],
  bundle: true,
  outfile: "dist/extension.js",
  external: ["vscode"],
  format: "cjs",
  platform: "node",
  target: "node20",
  sourcemap: !production,
  minify: production,
  logLevel: "info",
};

async function main() {
  if (watch) {
    console.log("[watch] build started");
    const extCtx = await esbuild.context(extensionConfig);
    await extCtx.watch();
    console.log("Watching for changes...");
  } else {
    await esbuild.build(extensionConfig);
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
