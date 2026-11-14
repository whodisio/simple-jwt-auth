import { MalfunctionError } from 'helpful-errors';
import { genTempDir } from 'test-fns';

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

/**
 * .what = the shape dpdm writes for one dependency edge
 */
interface DpdmDependency {
  issuer: string;
  request: string;
  id: string | null;
}

/**
 * .what = the shape dpdm writes for a whole walk: each file of the graph to its edges
 */
type DpdmTree = Record<string, DpdmDependency[] | null>;

/**
 * .what = the git root of this package
 */
const gitRoot: string = join(__dirname, '..', '..');

/**
 * .what = the parent of each file in the graph, on a shortest path from the entry
 * .why = a graph query of its own; the chain walk reads it, and any other report may too
 */
const getParentOfFileMap = (input: {
  tree: DpdmTree;
  entry: string;
}): Map<string, string> => {
  // breadth-first from the entry; the first parent recorded is on a shortest path
  // .note = deliberate mutation, scoped to this walk: a queue that grows as it is read
  const parentOf = new Map<string, string>();
  const queue = [input.entry];
  for (const current of queue) {
    for (const dependency of input.tree[current] ?? []) {
      if (!dependency.id || dependency.id === input.entry) continue;
      if (parentOf.has(dependency.id)) continue;
      parentOf.set(dependency.id, current);
      queue.push(dependency.id);
    }
  }
  return parentOf;
};

/**
 * .what = the require chain from the entry down to one file, entry first
 * .why = a red clamp names every hop, so the fix is plain: cut the hop that crossed sides
 */
const getChainToFile = (input: {
  parentOf: Map<string, string>;
  file: string;
}): string[] => {
  const parent = input.parentOf.get(input.file);
  return parent
    ? [...getChainToFile({ parentOf: input.parentOf, file: parent }), input.file]
    : [input.file];
};

/**
 * .what = cast a bare request into its package name
 * .why = `@scope/name/sub` and `name/sub` belong to one package; `node:crypto` is `crypto`
 */
const asPackageName = (input: { request: string }): string => {
  const request = input.request.replace(/^node:/, '');
  const segments = request.split('/');
  if (request.startsWith('@')) return segments.slice(0, 2).join('/');
  return segments[0] ?? request;
};

/**
 * .what = is this request a path into the graph, rather than a package?
 * .why = only bare requests leave the package; relative ones stay in the graph the walk already covers
 */
const isRelativeRequest = (input: { request: string }): boolean =>
  input.request.startsWith('.') || input.request.startsWith('/');

/**
 * .what = the key a reached dep sorts by: its package, then its issuer
 */
const asSortKey = (input: { dep: string; issuer: string }): string =>
  `${input.dep}:${input.issuer}`;

/**
 * .what = the order of two strings by code unit
 * .why = locale-free, so the report sorts the same on every host
 */
const asOrderOfStrings = (input: { a: string; b: string }): number =>
  input.a < input.b ? -1 : input.a > input.b ? 1 : 0;

/**
 * .what = cast a dpdm tree into the external deps it reaches, each with its chain
 * .why = keeps the walk's orchestrator a narrative; this is the one place a tree becomes a report
 * .note = sorted by dep, then issuer, so the report and its snapshot stay stable
 */
const asExternalDepsOfTree = (input: {
  tree: DpdmTree;
  entry: string;
}): { dep: string; request: string; issuer: string; chain: string[] }[] => {
  const parentOf = getParentOfFileMap(input);
  return Object.values(input.tree)
    .flatMap((dependencies) => dependencies ?? [])
    .filter((dependency) => !isRelativeRequest(dependency))
    .map((dependency) => ({
      dep: asPackageName(dependency),
      request: dependency.request,
      issuer: dependency.issuer,
      chain: [
        ...getChainToFile({ parentOf, file: dependency.issuer }),
        dependency.request,
      ],
    }))
    .sort((a, b) => asOrderOfStrings({ a: asSortKey(a), b: asSortKey(b) }));
};

/**
 * .what = cast the json dpdm writes into its tree
 * .why = a dpdm upgrade that moves `.tree` would else surface far below as a bare TypeError
 */
const asDpdmTreeOfOutputJson = (input: {
  json: string;
  entry: string;
}): DpdmTree => {
  const parsed = JSON.parse(input.json);
  if (typeof parsed?.tree !== 'object' || parsed.tree === null)
    throw new MalfunctionError('dpdm output holds no tree', {
      entry: input.entry,
      keys: Object.keys(parsed ?? {}),
      hint: 'dpdm may have changed its --output shape; compare node_modules/dpdm against the DependencyTree type',
    });
  const tree = parsed.tree as DpdmTree; // .note = dpdm's `--output` file is untyped json; this is the shape of its `DependencyTree` type

  // fail loud if the walk never reached the entry; else an empty report would read as a clean graph
  if (!(input.entry in tree))
    throw new MalfunctionError('dpdm output lacks the entry it was asked to walk', {
      entry: input.entry,
      filesWalked: Object.keys(tree).slice(0, 10),
      hint: 'confirm the entry path exists and is relative to the git root; a typo here would else pass the clamp',
    });
  return tree;
};

/**
 * .what = runs dpdm on one entry and returns the json it wrote
 * .why = dpdm runs as a child process, so it stays out of this repo's own cycle walk;
 *        a failed walk throws with dpdm's own stderr, so a red clamp names its cause
 */
const getDpdmOutputOfEntry = (input: {
  entry: string;
  extensions: string[] | null;
}): string => {
  // walk from the entry, stop at the package edge
  const output = join(genTempDir({ slug: 'dpdm-walk' }), 'tree.json');
  const args = [
    '--no-tree',
    '--no-circular',
    '--no-warning',
    '--no-progress',
    '--exclude',
    'node_modules',
    ...(input.extensions ? ['--extensions', input.extensions.join(',')] : []),
    '--output',
    output,
    input.entry,
  ];
  const walked = spawnSync(join(gitRoot, 'node_modules', '.bin', 'dpdm'), args, {
    cwd: gitRoot,
  });

  // fail loud if dpdm broke, or wrote naught, with its own words
  if (walked.error || walked.status !== 0 || !existsSync(output))
    throw new MalfunctionError('dpdm failed to walk the entry', {
      entry: input.entry,
      args,
      output,
      status: walked.status,
      error: walked.error?.message ?? null,
      stderr: walked.stderr?.toString('utf8') ?? null,
      hint: 'confirm the entry is built (npm run build) and that node_modules/.bin/dpdm is installed (pnpm install)',
    });
  return readFileSync(output, 'utf8');
};

/**
 * .what = walks the static require graph of one built entry and lists each
 *         external dep it reaches, with the file that asked for it
 * .why = the clamp for `simple-jwt-auth/unauthed`: the decode-side graph must
 *        reach no dep outside its allowlist
 * .note = dpdm visits every node of each file, so a `require()` nested in a
 *         function body counts the same as a top-level one. the walk stops at
 *         `node_modules`: it grades what our files ask for, not what a dep asks for
 */
export const getAllExternalDepsOfEntry = (input: {
  entry: string;

  /**
   * the file extensions a relative request may take, e.g. `['.d.ts']` to walk a
   * declaration graph; null keeps dpdm's own list (`.ts`, `.js`, …)
   */
  extensions: string[] | null;
}): {
  /**
   * the package name, e.g. `buffer`, `@scope/name` (a `node:` prefix is stripped)
   */
  dep: string;

  /**
   * the raw request, e.g. `jwk-to-pem`, `crypto`, `@scope/name/sub`
   */
  request: string;

  /**
   * the file in the graph that asked for it, relative to the git root
   */
  issuer: string;

  /**
   * the require chain from the entry down to the issuer, entry first
   */
  chain: string[];
}[] => {
  const entry = relative(gitRoot, input.entry);
  const json = getDpdmOutputOfEntry({ entry, extensions: input.extensions });
  const tree = asDpdmTreeOfOutputJson({ json, entry });
  return asExternalDepsOfTree({ tree, entry });
};
