import { buildSync } from 'esbuild';
import { ConstraintError, MalfunctionError } from 'helpful-errors';
import { x as extractTarball } from 'tar';
import { genTempDir, given, then, useBeforeAll, when } from 'test-fns';

import { execFileSync, spawnSync } from 'node:child_process';
import {
  cpSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { builtinModules } from 'node:module';
import { join } from 'node:path';
import { getThrownOfCall } from './.test/getThrownOfCall';
import { NAMES_OF_SUBPATH } from './.test/NAMES_OF_SUBPATH';
import { PACKAGES_OF_SIGNATURE_SIDE } from './.test/PACKAGES_OF_SIGNATURE_SIDE';

/**
 * .what = the git root of this package
 */
const gitRoot: string = join(__dirname, '..');

/**
 * .what = the packages the wish forbids in a browser bundle of the subpath
 */
const PACKAGES_FORBIDDEN: string[] = PACKAGES_OF_SIGNATURE_SIDE;

/**
 * .what = runs a command and returns its stdout as text
 * .why = a nonzero exit throws (execFileSync), so a broken pack or load fails the test loud
 */
const getStdoutOfCommand = (input: {
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv | null;
}): string =>
  execFileSync(input.command, input.args, {
    cwd: input.cwd,
    ...(input.env ? { env: input.env } : {}),
  }).toString('utf8');

/**
 * .what = an env for npm that reads no host config
 * .why = a host `.npmrc` or an inherited `npm_config_*` var would else steer the pack
 */
const getEnvOfNpmIsolated = (input: { dir: string }): NodeJS.ProcessEnv => {
  // npm refuses one file as both user and global config, so each gets its own
  const npmrcOfUser = join(input.dir, 'npmrc.user.empty');
  const npmrcOfGlobal = join(input.dir, 'npmrc.global.empty');
  writeFileSync(npmrcOfUser, '');
  writeFileSync(npmrcOfGlobal, '');
  return {
    ...Object.fromEntries(
      Object.entries(process.env).filter(
        ([key]) => !key.toLowerCase().startsWith('npm_config_'),
      ),
    ),
    npm_config_userconfig: npmrcOfUser,
    npm_config_globalconfig: npmrcOfGlobal,
  };
};

/**
 * .what = packs this package the way `npm publish` does, and unpacks it as a
 *         consumer's install would hold it
 * .why = the linked contract test sees the whole git root, so a stub absent
 *        from `files` passes there and breaks after release. the tarball holds
 *        only what ships
 * .note = runtime deps link to this repo's install, so each case here grades what
 *         the tarball ships, fast; the registry install of the published ranges
 *         is proven once, by genConsumerOfRegistryInstall (case3)
 */
const genConsumerOfPackedTarball = (input: {
  slug: string;
  filesOmitted: string[];
}): { dir: string; filesPacked: string[] } => {
  // take the real path of the temp dir: its link sits inside this repo, so a lookup from the link would climb into this repo's own node_modules
  const dir = realpathSync(genTempDir({ slug: input.slug }));
  const staged = join(dir, 'staged');

  // stage, pack, unpack, link
  setStageOfPackage({ staged, filesOmitted: input.filesOmitted });
  const packed = getTarballOfStage({ staged, destination: dir });
  setTarballUnpacked({ tarball: join(dir, packed.filename), dir });
  setRuntimeDepsLinked({ nodeModules: join(dir, 'node_modules') });
  return { dir, filesPacked: packed.files };
};

/**
 * .what = copies the git root into a stage dir, sans node_modules and dot dirs,
 *         with the named `files` entries dropped
 * .why = npm walks all of node_modules even though `files` decides what ships, so
 *        a stage packs fast; a dropped entry proves the test fails when one is forgotten
 */
const setStageOfPackage = (input: {
  staged: string;
  filesOmitted: string[];
}): void => {
  // copy each top-level entry; the stage dir is made first, so no entry order matters
  mkdirSync(input.staged, { recursive: true });
  for (const entry of readdirSync(gitRoot)) {
    if (entry === 'node_modules' || entry.startsWith('.')) continue;
    cpSync(join(gitRoot, entry), join(input.staged, entry), {
      recursive: true,
    });
  }

  // rewrite the staged `files` list
  const pathOfPkg = join(input.staged, 'package.json');
  const pkg = JSON.parse(readFileSync(pathOfPkg, 'utf8'));
  writeFileSync(
    pathOfPkg,
    JSON.stringify({
      ...pkg,
      files: asFilesWithout({ files: pkg.files, omitted: input.filesOmitted }),
    }),
  );
};

/**
 * .what = a `files` list with the named entries dropped
 */
const asFilesWithout = (input: {
  files: string[];
  omitted: string[];
}): string[] => input.files.filter((file) => !input.omitted.includes(file));

/**
 * .what = packs a stage dir with this repo's pinned npm, the way `npm publish` does
 * .why = a pinned npm with no host config packs the same on every machine;
 *        lifecycle hooks are skipped, as they would rebuild or init hooks
 */
const getTarballOfStage = (input: {
  staged: string;
  destination: string;
}): { filename: string; files: string[] } =>
  asTarballOfNpmPackJson({
    json: getStdoutOfCommand({
      command: join(gitRoot, 'node_modules', '.bin', 'npm'),
      args: [
        'pack',
        '--json',
        '--ignore-scripts',
        '--pack-destination',
        input.destination,
      ],
      cwd: input.staged,
      env: getEnvOfNpmIsolated({ dir: input.destination }),
    }),
  });

/**
 * .what = cast the json `npm pack --json` prints into the tarball name and its file list
 */
const asTarballOfNpmPackJson = (input: {
  json: string;
}): { filename: string; files: string[] } => {
  const [packed] = JSON.parse(input.json) as {
    filename: string;
    files: { path: string }[];
  }[]; // .note = npm's `pack --json` output is untyped json; this is its documented shape
  if (!packed)
    throw new MalfunctionError('npm pack reported no tarball', {
      json: input.json,
      hint: 'run node_modules/.bin/npm pack --json in the stage dir to see its output',
    });
  return {
    filename: packed.filename,
    files: packed.files.map((file) => file.path),
  };
};

/**
 * .what = unpacks a tarball into the consumer's node_modules, as an install holds it
 * .why = the pinned tar library unpacks the same on every host, with no tar binary off PATH
 */
const setTarballUnpacked = (input: { tarball: string; dir: string }): void => {
  const nodeModules = join(input.dir, 'node_modules');
  mkdirSync(nodeModules, { recursive: true });
  extractTarball({ sync: true, file: input.tarball, cwd: input.dir });
  renameSync(join(input.dir, 'package'), join(nodeModules, 'simple-jwt-auth'));
};

/**
 * .what = the names of this package's runtime deps, as its package.json declares them
 */
const getNamesOfRuntimeDeps = (): string[] =>
  Object.keys(
    (
      JSON.parse(readFileSync(join(gitRoot, 'package.json'), 'utf8')) as {
        dependencies: Record<string, string>;
      }
    ).dependencies,
  ); // .note = this package's own package.json; `dependencies` is its declared field

/**
 * .what = links each runtime dep of this package from this repo's install
 */
const setRuntimeDepsLinked = (input: { nodeModules: string }): void => {
  for (const dep of getNamesOfRuntimeDeps()) {
    const target = realpathSync(join(gitRoot, 'node_modules', dep));
    mkdirSync(join(input.nodeModules, dep, '..'), { recursive: true });
    symlinkSync(target, join(input.nodeModules, dep), 'dir');
  }
};

/**
 * .what = packs this package, then installs the tarball into an empty consumer
 *         with this repo's pinned npm, its runtime deps fetched from the registry
 * .why = the linked consumer cannot see a published range that no longer
 *        installs, or a dep the package uses but does not declare; a real
 *        install from the registry can
 * .note = dep install scripts are skipped, so a dep's own postinstall cannot add
 *         network flake; none of this package's deps needs one to load
 */
const genConsumerOfRegistryInstall = (input: {
  slug: string;
}): { dir: string } => {
  // take the real path, for the same reason as genConsumerOfPackedTarball
  const dir = realpathSync(genTempDir({ slug: input.slug }));
  const staged = join(dir, 'staged');
  const consumer = join(dir, 'consumer');

  // stage and pack, as above
  setStageOfPackage({ staged, filesOmitted: [] });
  const packed = getTarballOfStage({ staged, destination: dir });

  // install the tarball into an empty consumer, as `npm install <tarball>` does
  mkdirSync(consumer, { recursive: true });
  writeFileSync(
    join(consumer, 'package.json'),
    JSON.stringify({ name: 'consumer-of-registry-install', private: true }),
  );
  getStdoutOfCommand({
    command: join(gitRoot, 'node_modules', '.bin', 'npm'),
    args: [
      'install',
      join(dir, packed.filename),
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
    ],
    cwd: consumer,
    env: getEnvOfNpmIsolated({ dir }),
  });
  return { dir: consumer };
};

/**
 * .what = the files the subpath needs in the tarball
 */
const FILES_OF_SUBPATH: string[] = [
  'unauthed/package.json',
  'dist/unauthed.js',
  'dist/unauthed.d.ts',
];

/**
 * .what = fails loud if the tarball lacks a file the subpath needs, and names the fix
 * .why = a stub dropped from `files` breaks every legacy consumer after release; ci names the fix first
 */
const assertSubpathShips = (input: { filesPacked: string[] }): void => {
  const absent = FILES_OF_SUBPATH.filter(
    (file) => !input.filesPacked.includes(file),
  );
  if (absent.length > 0)
    throw new ConstraintError(
      [
        'published tarball lacks the unauthed subpath',
        ...absent.map((file) => `   ├─ absent: ${file}`),
        '   └─ fix: add "/unauthed" to package.json files, and confirm `npm run build` emits dist/unauthed.*',
      ].join('\n'),
    );
};

/**
 * .what = the shipped files a consumer of the subpath meets: the stub, the
 *         subpath's own dist files, and every file outside dist
 * .why = a snapshot of this set stays still when an unrelated source file is added
 */
const asFilesOfSubpathSurface = (input: { files: string[] }): string[] =>
  input.files
    .filter(
      (file) => !file.startsWith('dist/') || file.startsWith('dist/unauthed'),
    )
    .sort();

/**
 * .what = the compiler options each ts `moduleResolution` mode needs, over the consumers' base
 * .why = the readme names each mode; each one here is a mode a consumer may compile on
 * .note = node10 is the base's own mode, so it adds naught
 */
const COMPILER_OPTIONS_OF_MODE = {
  node10: {},
  node16: { module: 'node16', moduleResolution: 'node16' },
  nodenext: { module: 'nodenext', moduleResolution: 'nodenext' },
  bundler: { module: 'esnext', moduleResolution: 'bundler' },
} as const;

/**
 * .what = compiles a set of consumer sources against the unpacked package, in one ts
 *         program per mode, and returns the diagnostics of each source
 * .why = proves the types load under the consumer's own ts mode; one program per
 *        mode keeps the tsc runs few
 */
const getDiagnosticsOfConsumers = <TSlug extends string>(input: {
  dir: string;
  moduleResolution: keyof typeof COMPILER_OPTIONS_OF_MODE;
  sources: Record<TSlug, string | { source: string; extension: '.mts' }>;
}): Record<TSlug, string[]> => {
  // write each consumer source, and one tsconfig that holds them all
  const files = Object.entries<string | { source: string; extension: '.mts' }>(
    input.sources,
  ).map(([slug, entry]) => {
    const { source, extension } = asConsumerSourceOfEntry({ entry });
    const name = `consumer.${input.moduleResolution}.${slug}${extension}`;
    const file = join(input.dir, name);
    writeFileSync(file, source);
    return { slug, file, name };
  });
  const configPath = join(input.dir, `tsconfig.${input.moduleResolution}.json`);
  writeFileSync(
    configPath,
    JSON.stringify(
      asTsconfigOfConsumer({
        files: files.map((entry) => entry.file),
        moduleResolution: input.moduleResolution,
      }),
    ),
  );

  // compile once, then sort the diagnostics by the file they name
  const diagnostics = getDiagnosticsOfTsc({ configPath, cwd: input.dir });
  return Object.fromEntries(
    files.map(({ slug, name }) => [
      slug,
      diagnostics.filter((line) => line.includes(name)),
    ]),
  ) as Record<TSlug, string[]>; // .note = Object.fromEntries widens its keys to string; the keys here are exactly the slugs of input.sources
};

/**
 * .what = the text and file extension of one consumer source
 * .why = a bare string is a cjs-format `.ts`; an esm-format consumer names `.mts`
 */
const asConsumerSourceOfEntry = (input: {
  entry: string | { source: string; extension: '.mts' };
}): { source: string; extension: '.ts' | '.mts' } =>
  typeof input.entry === 'string'
    ? { source: input.entry, extension: '.ts' }
    : input.entry;

/**
 * .what = a tsconfig for consumer files, over the consumers' base, in one ts mode
 */
const asTsconfigOfConsumer = (input: {
  files: string[];
  moduleResolution: keyof typeof COMPILER_OPTIONS_OF_MODE;
}): object => ({
  extends: join(
    gitRoot,
    'node_modules',
    '@tsconfig',
    'node-lts-strictest',
    'tsconfig.json',
  ),
  compilerOptions: {
    noEmit: true,
    types: [],
    // the base sets `importsNotUsedAsValues`, which this repo's ts flags as deprecated; a fact of the base, not of our types
    ignoreDeprecations: '5.0',
    ...COMPILER_OPTIONS_OF_MODE[input.moduleResolution],
  },
  files: input.files,
});

/**
 * .what = the `error TS` lines of tsc's stdout
 */
const asDiagnosticsOfTscStdout = (input: { stdout: string }): string[] =>
  input.stdout.split('\n').filter((line) => line.includes('error TS'));

/**
 * .what = runs tsc on one tsconfig and returns its diagnostics
 * .why = tsc runs as a child process, which keeps typescript out of this repo's own
 *        cycle walk; tsc exits 2 on diagnostics, so stdout is read either way
 */
const getDiagnosticsOfTsc = (input: {
  configPath: string;
  cwd: string;
}): string[] => {
  // compile
  const compiled = spawnSync(
    join(gitRoot, 'node_modules', '.bin', 'tsc'),
    ['-p', input.configPath, '--pretty', 'false'],
    { cwd: input.cwd },
  );
  const diagnostics = asDiagnosticsOfTscStdout({
    stdout: compiled.stdout?.toString('utf8') ?? '',
  });

  // fail loud if tsc broke rather than reported; else a crash would read as "no diagnostics"
  if (compiled.error || (compiled.status !== 0 && diagnostics.length === 0))
    throw new MalfunctionError('tsc failed to compile the consumer fixture', {
      status: compiled.status,
      error: compiled.error?.message ?? null,
      stderr: compiled.stderr?.toString('utf8') ?? null,
      configPath: input.configPath,
      hint: 'confirm node_modules/.bin/tsc and @tsconfig/node-lts-strictest are installed (pnpm install), then run tsc -p on the configPath above to see its output',
    });
  return diagnostics;
};

/**
 * .what = bundles one consumer source with esbuild, and returns the packages the bundle holds
 * .why = the direct proof of the wish: what a bundler pulls into a page from this import
 * .note = esbuild's own api, from this repo's pinned install; a failed build throws with its errors
 */
const getPackagesOfBundle = (input: {
  dir: string;
  slug: string;
  source: string;
  platform: 'browser' | 'node';
  external: string[];
}): string[] => {
  // write the consumer, then bundle it in memory with a metafile
  const entry = join(input.dir, `bundle.${input.slug}.mjs`);
  writeFileSync(entry, input.source);
  const bundled = buildSync({
    entryPoints: [entry],
    absWorkingDir: input.dir,
    bundle: true,
    platform: input.platform,
    external: input.external,
    format: 'esm',
    logLevel: 'silent',
    metafile: true,
    write: false,
  });

  // read the package of each input file; the page's own entry is no package, so it drops out
  return [
    ...new Set(
      Object.keys(bundled.metafile.inputs)
        .map((path) => asPackageOfBundleInput({ path }))
        .filter((pkg): pkg is string => pkg !== null),
    ),
  ].sort();
};

/**
 * .what = the package a bundled file belongs to, read from its path; null for a file outside node_modules
 * .why = the deepest `node_modules/` segment names the package, through any pnpm store dir
 */
const asPackageOfBundleInput = (input: { path: string }): string | null => {
  const segments = input.path.split('node_modules/');
  if (segments.length < 2) return null;
  const tail = (segments[segments.length - 1] ?? '').split('/');
  return tail[0]?.startsWith('@')
    ? `${tail[0]}/${tail[1] ?? ''}`
    : (tail[0] ?? input.path);
};

/**
 * .what = the loaded module paths that sit inside a signature-side package
 * .why = the runtime twin of the clamp: names the heavy packages the wish forbids
 */
const getModulesOfSignatureSide = (input: { modules: string[] }): string[] =>
  input.modules.filter((path) =>
    PACKAGES_FORBIDDEN.some(
      (name) => path.includes(`/${name}/`) || path.includes(`\\${name}\\`),
    ),
  );

/**
 * .what = the load report with each consumer path made relative to the consumer dir
 * .why = the temp dir differs per run; relative paths keep the snapshot stable
 * .note = the dir is matched in its json-escaped form, so a windows path with backslashes is masked too
 */
const asReportRelativeToConsumer = (input: {
  report: Record<string, unknown>;
  dir: string;
}): Record<string, unknown> =>
  JSON.parse(
    JSON.stringify(input.report)
      .split(JSON.stringify(input.dir).slice(1, -1))
      .join('<consumer>'),
  );

/**
 * .what = a consumer that uses the full decode-side contract
 */
const SOURCE_CONSUMER_OF_CONTRACT: string = `
import {
  getUnauthedClaims,
  getUnauthedHeaderClaims,
  isJSONWebToken,
  redactSignature,
  SimpleJwtAuthError,
  type MinimalTokenClaims,
  type MinimalTokenHeaderClaims,
} from 'simple-jwt-auth/unauthed';

export const readToken = (input: { token: string }) => {
  if (!isJSONWebToken(input.token)) throw new SimpleJwtAuthError('not a jwt');
  const claims: MinimalTokenClaims = getUnauthedClaims({ token: input.token });
  const header: MinimalTokenHeaderClaims = getUnauthedHeaderClaims({ token: input.token });
  const redacted: string = redactSignature({ token: input.token });
  return { sub: claims.sub, alg: header.alg, redacted };
};
`;

/**
 * .what = a consumer that misuses a decoded claim's type
 * .why = proves the import carries real types, not `any`
 */
const SOURCE_CONSUMER_OF_WRONG_USE: string = `
import { getUnauthedClaims } from 'simple-jwt-auth/unauthed';
export const sub: number = getUnauthedClaims({ token: 'a.b.c' }).sub;
`;

/**
 * .what = a consumer that misuses a decoded header's type
 * .why = the header type reaches into another module; under skipLibCheck an unresolved
 *        import there would read as `any`, and this line would compile
 */
const SOURCE_CONSUMER_OF_WRONG_USE_OF_HEADER: string = `
import { getUnauthedHeaderClaims } from 'simple-jwt-auth/unauthed';
export const alg: number = getUnauthedHeaderClaims({ token: 'a.b.c' }).alg;
`;

/**
 * .what = a consumer that takes the decode-side contract from the root
 * .why = the root re-exports the subpath; its types must carry through too
 */
const SOURCE_CONSUMER_OF_ROOT_CONTRACT: string = `
import { getUnauthedClaims, type MinimalTokenClaims } from 'simple-jwt-auth';
export const claims: MinimalTokenClaims = getUnauthedClaims({ token: 'a.b.c' });
`;

/**
 * .what = an esm-format consumer (`.mts`) that imports the subpath
 * .why = pins that tsc accepts this import, which node refuses at runtime; the gap the readme warns of
 */
const SOURCE_CONSUMER_ESM_OF_SUBPATH: string = `
import { getUnauthedClaims } from 'simple-jwt-auth/unauthed';
export const decode = getUnauthedClaims;
`;

/**
 * .what = an esm-format consumer (`.mts`) that imports the decode op from the root
 * .why = the readme sends esm consumers to the root; its types must load there
 */
const SOURCE_CONSUMER_ESM_OF_ROOT: string = `
import { getUnauthedClaims } from 'simple-jwt-auth';
export const decode = getUnauthedClaims;
`;

/**
 * .what = a consumer that asks the subpath for a verify op, and for a decode-adjacent op the root alone holds
 */
const SOURCE_CONSUMER_OF_VERIFY_OP: string = `
import { getAuthedClaims } from 'simple-jwt-auth/unauthed';
import { isExpiredToken } from 'simple-jwt-auth/unauthed';
export const verify = getAuthedClaims;
export const isExpired = isExpiredToken;
`;

/**
 * .what = a browser page that imports the decode ops from the subpath
 */
const SOURCE_BUNDLE_OF_SUBPATH: string = `
import { getUnauthedClaims, redactSignature } from 'simple-jwt-auth/unauthed';
console.log(getUnauthedClaims, redactSignature);
`;

/**
 * .what = a page that imports the same op from the root, the shape the wish moves away from
 */
const SOURCE_BUNDLE_OF_ROOT: string = `
import { getUnauthedClaims } from 'simple-jwt-auth';
console.log(getUnauthedClaims);
`;

/**
 * .what = a node program that requires both entries and reports what loaded
 */
const SOURCE_PROGRAM_OF_RUNTIME: string = [
  "const unauthed = require('simple-jwt-auth/unauthed');",
  'const modulesAfterSubpath = Object.keys(require.cache);',
  "const root = require('simple-jwt-auth');",
  'console.log(JSON.stringify({',
  "  pathOfSubpath: require.resolve('simple-jwt-auth/unauthed'),",
  "  pathOfRoot: require.resolve('simple-jwt-auth'),",
  '  namesOfSubpath: Object.keys(unauthed).sort(),',
  "  isRootLoaded: typeof root.getAuthedClaims === 'function',",
  '  isOneErrorClass: unauthed.SimpleJwtAuthError === root.SimpleJwtAuthError,',
  '  modulesAfterSubpath,',
  '}));',
].join('\n');

describe('unauthed.tarball', () => {
  given(
    '[case1] the package, packed and unpacked as a consumer gets it',
    () => {
      const consumer = useBeforeAll(async () =>
        genConsumerOfPackedTarball({
          slug: 'unauthed-tarball',
          filesOmitted: [],
        }),
      );

      when('[t0] the tarball contents are listed', () => {
        then('it holds the stub and the built subpath entry', () => {
          expect(consumer.filesPacked).toEqual(
            expect.arrayContaining(FILES_OF_SUBPATH),
          );
          expect(() =>
            assertSubpathShips({ filesPacked: consumer.filesPacked }),
          ).not.toThrow();
        });

        then(
          'the files a subpath consumer meets are the stub, the subpath dist files, and the top-level package files',
          () => {
            expect(
              asFilesOfSubpathSurface({ files: consumer.filesPacked }),
            ).toMatchSnapshot();
          },
        );
      });

      when('[t1] node requires both entries from the unpacked install', () => {
        const loaded = useBeforeAll(async () =>
          JSON.parse(
            getStdoutOfCommand({
              command: process.execPath,
              args: ['-e', SOURCE_PROGRAM_OF_RUNTIME],
              cwd: consumer.dir,
              env: null,
            }),
          ),
        );

        then('the subpath loads with the five decode-side names', () => {
          expect(loaded.namesOfSubpath).toEqual([...NAMES_OF_SUBPATH].sort());
        });

        then('the subpath alone loads none of the signature-side deps', () => {
          expect(
            getModulesOfSignatureSide({ modules: loaded.modulesAfterSubpath }),
          ).toEqual([]);
        });

        then('the root still loads, with the same error class', () => {
          expect(loaded.isRootLoaded).toBe(true);
          expect(loaded.isOneErrorClass).toBe(true);
        });

        then(
          'each entry lands on its built file, via the stub and main',
          () => {
            expect(loaded.pathOfSubpath).toMatch(
              /node_modules[\\/]simple-jwt-auth[\\/]dist[\\/]unauthed\.js$/,
            );
            expect(loaded.pathOfRoot).toMatch(
              /node_modules[\\/]simple-jwt-auth[\\/]dist[\\/]index\.js$/,
            );
          },
        );

        then(
          'the load report names each entry file and every module the subpath alone loaded',
          () => {
            expect(
              asReportRelativeToConsumer({ report: loaded, dir: consumer.dir }),
            ).toMatchSnapshot();
          },
        );
      });

      when('[t2] native node esm imports each entry', () => {
        then(
          'the subpath is refused, as the readme states (a directory stub is cjs-only)',
          () => {
            const imported = spawnSync(
              process.execPath,
              [
                '--input-type=module',
                '-e',
                "import 'simple-jwt-auth/unauthed';",
              ],
              { cwd: consumer.dir },
            );
            expect(imported.status).not.toEqual(0);
            expect(imported.stderr.toString('utf8')).toContain(
              'ERR_UNSUPPORTED_DIR_IMPORT',
            );

            // snap the one line a consumer meets, with the temp dir masked
            const lineOfError = imported.stderr
              .toString('utf8')
              .split('\n')
              .find((line) =>
                line.startsWith('Error [ERR_UNSUPPORTED_DIR_IMPORT]'),
              );
            expect(
              asReportRelativeToConsumer({
                report: { lineOfError },
                dir: consumer.dir,
              }),
            ).toMatchSnapshot();
          },
        );

        then('the root imports, as the readme directs', () => {
          const imported = getStdoutOfCommand({
            command: process.execPath,
            args: [
              '--input-type=module',
              '-e',
              "import root from 'simple-jwt-auth'; console.log(typeof root.getUnauthedClaims);",
            ],
            cwd: consumer.dir,
            env: null,
          });
          expect(imported.trim()).toEqual('function');
        });

        then(
          'a named import from the root works too, through the re-export',
          () => {
            const imported = getStdoutOfCommand({
              command: process.execPath,
              args: [
                '--input-type=module',
                '-e',
                "import { getUnauthedClaims, redactSignature } from 'simple-jwt-auth'; console.log(typeof getUnauthedClaims, typeof redactSignature);",
              ],
              cwd: consumer.dir,
              env: null,
            });
            expect(imported.trim()).toEqual('function function');
          },
        );
      });

      when('[t3] a browser page that imports the subpath is bundled', () => {
        const bundle = useBeforeAll(async () => ({
          packages: getPackagesOfBundle({
            dir: consumer.dir,
            slug: 'subpath',
            source: SOURCE_BUNDLE_OF_SUBPATH,
            platform: 'browser',
            external: [],
          }),
        }));

        then('the bundle holds none of the signature-side packages', () => {
          expect(
            bundle.packages.filter((name) => PACKAGES_FORBIDDEN.includes(name)),
          ).toEqual([]);
          expect(bundle.packages).toContain('simple-jwt-auth');
        });

        then(
          'the bundle holds simple-jwt-auth and buffer with its own deps, no more',
          () => {
            expect(bundle.packages).toMatchSnapshot();
          },
        );
      });

      when(
        '[t4] the same op is bundled from the root, for contrast, with node builtins left external, so buffer and crypto are not listed',
        () => {
          // same platform as [t3]; node builtins stay external, as a browser page would polyfill or shim them
          const bundle = useBeforeAll(async () => ({
            packages: getPackagesOfBundle({
              dir: consumer.dir,
              slug: 'root',
              source: SOURCE_BUNDLE_OF_ROOT,
              platform: 'browser',
              external: [
                ...builtinModules,
                ...builtinModules.map((name) => `node:${name}`),
              ],
            }),
          }));

          then(
            'the bundle holds the signature-side packages, so the subpath check above can bite',
            () => {
              expect(bundle.packages).toEqual(
                expect.arrayContaining([
                  'jwk-to-pem',
                  'elliptic',
                  'axios',
                  'parse-domain',
                ]),
              );
              expect(bundle.packages).toMatchSnapshot();
            },
          );
        },
      );

      when('[t5] a consumer compiles against it on ts node10', () => {
        const compiled = useBeforeAll(async () =>
          getDiagnosticsOfConsumers({
            dir: consumer.dir,
            moduleResolution: 'node10',
            sources: {
              contract: SOURCE_CONSUMER_OF_CONTRACT,
              wrongUse: SOURCE_CONSUMER_OF_WRONG_USE,
              wrongUseOfHeader: SOURCE_CONSUMER_OF_WRONG_USE_OF_HEADER,
              rootContract: SOURCE_CONSUMER_OF_ROOT_CONTRACT,
              verifyOp: SOURCE_CONSUMER_OF_VERIFY_OP,
            },
          }),
        );

        then('the contract types load with no diagnostics', () => {
          expect(compiled.contract).toEqual([]);
        });

        then('the root carries the same contract types', () => {
          expect(compiled.rootContract).toEqual([]);
        });

        then('a wrong use of a decoded claim fails the compile', () => {
          expect(compiled.wrongUse.join('\n')).toMatch(
            /Type 'string' is not assignable to type 'number'/,
          );
          expect(
            asReportRelativeToConsumer({
              report: { diagnostics: compiled.wrongUse },
              dir: consumer.dir,
            }),
          ).toMatchSnapshot();
        });

        then(
          'a wrong use of a decoded header fails the compile, so its type is not any',
          () => {
            expect(compiled.wrongUseOfHeader.join('\n')).toMatch(
              /is not assignable to type 'number'/,
            );
            expect(
              asReportRelativeToConsumer({
                report: { diagnostics: compiled.wrongUseOfHeader },
                dir: consumer.dir,
              }),
            ).toMatchSnapshot();
          },
        );

        then(
          'a verify op, and a decode-adjacent op the root alone holds, are refused at the import',
          () => {
            expect(compiled.verifyOp.join('\n')).toMatch(
              /has no exported member (named )?'getAuthedClaims'/,
            );
            expect(compiled.verifyOp.join('\n')).toMatch(
              /has no exported member (named )?'isExpiredToken'/,
            );
            expect(
              asReportRelativeToConsumer({
                report: { diagnostics: compiled.verifyOp },
                dir: consumer.dir,
              }),
            ).toMatchSnapshot();
          },
        );
      });

      when('[t6] a consumer compiles against it on ts node16', () => {
        const compiled = useBeforeAll(async () =>
          getDiagnosticsOfConsumers({
            dir: consumer.dir,
            moduleResolution: 'node16',
            sources: {
              contract: SOURCE_CONSUMER_OF_CONTRACT,
              verifyOp: SOURCE_CONSUMER_OF_VERIFY_OP,
            },
          }),
        );

        then('the contract types load with no diagnostics', () => {
          expect(compiled.contract).toEqual([]);
        });

        then(
          'a verify op, and a decode-adjacent op the root alone holds, are refused at the import',
          () => {
            expect(compiled.verifyOp.join('\n')).toMatch(
              /has no exported member (named )?'getAuthedClaims'/,
            );
            expect(compiled.verifyOp.join('\n')).toMatch(
              /has no exported member (named )?'isExpiredToken'/,
            );
            expect(
              asReportRelativeToConsumer({
                report: { diagnostics: compiled.verifyOp },
                dir: consumer.dir,
              }),
            ).toMatchSnapshot();
          },
        );
      });

      when('[t7] a consumer compiles against it on ts nodenext', () => {
        const compiled = useBeforeAll(async () =>
          getDiagnosticsOfConsumers({
            dir: consumer.dir,
            moduleResolution: 'nodenext',
            sources: {
              contract: SOURCE_CONSUMER_OF_CONTRACT,
              verifyOp: SOURCE_CONSUMER_OF_VERIFY_OP,
              esmOfSubpath: {
                source: SOURCE_CONSUMER_ESM_OF_SUBPATH,
                extension: '.mts',
              },
              esmOfRoot: {
                source: SOURCE_CONSUMER_ESM_OF_ROOT,
                extension: '.mts',
              },
            },
          }),
        );

        then('the contract types load with no diagnostics', () => {
          expect(compiled.contract).toEqual([]);
        });

        // .note = tsc accepts what node refuses at runtime ([t2], ERR_UNSUPPORTED_DIR_IMPORT); the readme warns of this gap
        then(
          'an esm-format file compiles against the subpath, though node refuses it at runtime',
          () => {
            expect(compiled.esmOfSubpath).toEqual([]);
          },
        );

        then('an esm-format file compiles against the root', () => {
          expect(compiled.esmOfRoot).toEqual([]);
        });

        then(
          'a verify op, and a decode-adjacent op the root alone holds, are refused at the import',
          () => {
            expect(compiled.verifyOp.join('\n')).toMatch(
              /has no exported member (named )?'getAuthedClaims'/,
            );
            expect(compiled.verifyOp.join('\n')).toMatch(
              /has no exported member (named )?'isExpiredToken'/,
            );
            expect(
              asReportRelativeToConsumer({
                report: { diagnostics: compiled.verifyOp },
                dir: consumer.dir,
              }),
            ).toMatchSnapshot();
          },
        );
      });

      when('[t8] a consumer compiles against it on ts bundler', () => {
        const compiled = useBeforeAll(async () =>
          getDiagnosticsOfConsumers({
            dir: consumer.dir,
            moduleResolution: 'bundler',
            sources: {
              contract: SOURCE_CONSUMER_OF_CONTRACT,
              verifyOp: SOURCE_CONSUMER_OF_VERIFY_OP,
            },
          }),
        );

        then('the contract types load with no diagnostics', () => {
          expect(compiled.contract).toEqual([]);
        });

        then(
          'a verify op, and a decode-adjacent op the root alone holds, are refused at the import',
          () => {
            expect(compiled.verifyOp.join('\n')).toMatch(
              /has no exported member (named )?'getAuthedClaims'/,
            );
            expect(compiled.verifyOp.join('\n')).toMatch(
              /has no exported member (named )?'isExpiredToken'/,
            );
            expect(
              asReportRelativeToConsumer({
                report: { diagnostics: compiled.verifyOp },
                dir: consumer.dir,
              }),
            ).toMatchSnapshot();
          },
        );
      });
    },
  );

  given('[case2] a files list that omits /unauthed, packed as above', () => {
    const consumer = useBeforeAll(async () =>
      genConsumerOfPackedTarball({
        slug: 'unauthed-tarball-redcase',
        filesOmitted: ['/unauthed'],
      }),
    );

    when('[t0] the tarball contents are listed', () => {
      then('the stub is absent, though dist/unauthed.js ships', () => {
        expect(consumer.filesPacked).not.toContain('unauthed/package.json');
        expect(consumer.filesPacked).toContain('dist/unauthed.js');
      });

      then(
        'the check fails loud, and names the absent path and the fix',
        () => {
          const thrown = getThrownOfCall({
            call: () =>
              assertSubpathShips({ filesPacked: consumer.filesPacked }),
          });
          expect(thrown.name).toEqual('ConstraintError');
          expect(thrown.message).toContain('absent: unauthed/package.json');
          expect(thrown.message).toContain('fix: add "/unauthed"');
          expect(thrown.message).toMatchSnapshot();
        },
      );
    });

    when('[t1] node requires the subpath from the unpacked install', () => {
      then('it fails to find the module', () => {
        const required = spawnSync(
          process.execPath,
          ['-e', "require('simple-jwt-auth/unauthed')"],
          { cwd: consumer.dir },
        );
        expect(required.status).not.toEqual(0);
        expect(required.stderr.toString('utf8')).toContain(
          "Cannot find module 'simple-jwt-auth/unauthed'",
        );
        expect(
          required.stderr
            .toString('utf8')
            .split('\n')
            .find((line) => line.includes('Cannot find module')),
        ).toMatchSnapshot();
      });
    });

    when('[t2] a node10 consumer compiles the contract against it', () => {
      then('tsc fails loud on the absent module', () => {
        const compiled = getDiagnosticsOfConsumers({
          dir: consumer.dir,
          moduleResolution: 'node10',
          sources: { contract: SOURCE_CONSUMER_OF_CONTRACT },
        });
        expect(compiled.contract.join('\n')).toMatch(
          /Cannot find module 'simple-jwt-auth\/unauthed'/,
        );
        expect(
          asReportRelativeToConsumer({
            report: { diagnostics: compiled.contract },
            dir: consumer.dir,
          }),
        ).toMatchSnapshot();
      });
    });
  });

  given(
    '[case3] the packed tarball, installed from the npm registry as a consumer installs it',
    () => {
      const consumer = useBeforeAll(async () =>
        genConsumerOfRegistryInstall({ slug: 'unauthed-tarball-registry' }),
      );

      when('[t0] node requires both entries from the install', () => {
        const loaded = useBeforeAll(async () =>
          JSON.parse(
            getStdoutOfCommand({
              command: process.execPath,
              args: ['-e', SOURCE_PROGRAM_OF_RUNTIME],
              cwd: consumer.dir,
              env: null,
            }),
          ),
        );

        then(
          'each runtime dep was fetched into the install, not linked to this repo',
          () => {
            for (const dep of getNamesOfRuntimeDeps())
              expect({
                dep,
                isLink: lstatSync(
                  join(consumer.dir, 'node_modules', dep),
                ).isSymbolicLink(),
              }).toEqual({ dep, isLink: false });
          },
        );

        then('the subpath loads with the five decode-side names', () => {
          expect(loaded.namesOfSubpath).toEqual([...NAMES_OF_SUBPATH].sort());
        });

        then('the subpath alone loads none of the signature-side deps', () => {
          expect(
            getModulesOfSignatureSide({ modules: loaded.modulesAfterSubpath }),
          ).toEqual([]);
        });

        then(
          'the root loads on the published ranges, with the same error class',
          () => {
            expect(loaded.isRootLoaded).toBe(true);
            expect(loaded.isOneErrorClass).toBe(true);
          },
        );
      });
    },
  );
});
