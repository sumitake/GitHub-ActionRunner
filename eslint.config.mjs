import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/node_modules/**",
      "**/dist/**",
      "**/.wrangler/**",
      "**/worker-configuration.d.ts",
    ],
  },
  {
    files: ["worker/**/*.ts"],
    extends: [tseslint.configs.recommended],
  },
);
