import { execFile } from "child_process";
import * as vscode from "vscode";
import { CLIErrorPayload } from "./types";

/**
 * Thrown for every CLI failure. `payload` holds the parsed structured JSON
 * error when imgowner wrote one to stderr (every documented failure path
 * does); `message` is always a string safe to show the user directly, falling
 * back to raw stderr/stdout when stderr wasn't valid JSON (e.g. the binary
 * itself is missing, so there was no imgowner process to write one).
 */
export class CLIError extends Error {
  constructor(
    message: string,
    public readonly exitCode: number | null,
    public readonly payload?: CLIErrorPayload,
  ) {
    super(message);
    this.name = "CLIError";
  }
}

export function getBinaryPath(): string {
  return vscode.workspace.getConfiguration("imgowner").get<string>("binaryPath") || "imgowner";
}

export function getConfigPath(): string {
  return vscode.workspace.getConfiguration("imgowner").get<string>("configPath") || ".imgowner.yaml";
}

export function getImageRef(resource?: vscode.Uri): string {
  return (
    vscode.workspace.getConfiguration("imgowner", resource).get<string>("image") || ""
  );
}

/**
 * Runs `imgowner <args>` and parses stdout as JSON.
 *
 * imgowner's documented exit codes are 0 (success), 1 (policy breach --
 * `ci` only, not used by any command this extension calls) and 2
 * (tool/config error, with a JSON payload on stderr). A non-JSON stderr means
 * the failure happened before imgowner's own error handling ran at all --
 * most commonly ENOENT because the binary isn't on PATH.
 */
export async function runJSON<T>(
  args: string[],
  cwd: string,
  output: vscode.OutputChannel,
): Promise<{ data: T; warnings: string[] }> {
  const { stdout, warnings } = await run(args, cwd, output);
  const parsed = tryParseJSON<T>(stdout);
  if (parsed === undefined) {
    throw new CLIError(
      "imgowner produced output that was not valid JSON. See the Output panel for the raw response.",
      0,
    );
  }
  return { data: parsed, warnings };
}

export interface RunResult {
  stdout: string;
  /**
   * Lines imgowner wrote to stderr as "warning: ..." on a successful run --
   * for example a pin lookup that couldn't reach Docker, or a base image
   * boundary that couldn't be verified. The command still succeeded, but its
   * results are degraded and the user needs to know why.
   */
  warnings: string[];
}

/** Runs `imgowner <args>` and resolves on exit code 0. */
export function run(args: string[], cwd: string, output: vscode.OutputChannel): Promise<RunResult> {
  const bin = getBinaryPath();
  output.appendLine(`$ ${bin} ${args.join(" ")}`);

  return new Promise((resolve, reject) => {
    execFile(
      bin,
      args,
      { cwd, maxBuffer: 20 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (stderr) {
          output.appendLine(stderr.trimEnd());
        }

        if (err) {
          if ((err as NodeJS.ErrnoException).code === "ENOENT") {
            reject(
              new CLIError(
                `imgowner binary not found ("${bin}"). Install it and ensure it's on PATH, ` +
                  `or set the "imgowner.binaryPath" setting.`,
                null,
              ),
            );
            return;
          }

          const exitCode = (err as NodeJS.ErrnoException & { code?: number | string }).code;
          const numericExit = typeof exitCode === "number" ? exitCode : null;

          const payload = tryParseJSON<CLIErrorPayload>(stderr);
          if (payload) {
            const msg = payload.error ?? "imgowner failed";
            const hint = payload.hint ? ` (${payload.hint})` : "";
            reject(new CLIError(msg + hint, numericExit, payload));
            return;
          }

          reject(
            new CLIError(
              stderr.trim() || err.message,
              numericExit,
            ),
          );
          return;
        }

        resolve({ stdout, warnings: parseWarnings(stderr) });
      },
    );
  });
}

/**
 * Collects "warning: ..." entries from stderr. imgowner indents continuation
 * lines ("  reason: ...") under a warning, so those are folded into the entry
 * they belong to rather than reported on their own.
 */
export function parseWarnings(stderr: string): string[] {
  const warnings: string[] = [];
  for (const line of stderr.split(/\r?\n/)) {
    if (line.startsWith("warning:")) {
      warnings.push(line.slice("warning:".length).trim());
    } else if (/^\s+\S/.test(line) && warnings.length > 0) {
      warnings[warnings.length - 1] += " " + line.trim();
    }
  }
  return warnings;
}

function tryParseJSON<T>(text: string): T | undefined {
  const trimmed = text.trim();
  if (!trimmed) {
    return undefined;
  }
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    return undefined;
  }
}
