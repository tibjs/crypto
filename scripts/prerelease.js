const fse = require('fs-extra');
const path = require('path');
const ora = require('ora');
const chalk = require('chalk');

const pkgRoot = path.join(__dirname, '../');
const distDir = 'dist';

const withSpinner = (promise, text) => {
  ora.promise(promise, {
    text,
  });
  return promise;
};

const copyRelationalFiles = (pathRootDir, pathDistDir) =>
  Promise.all(
    ['package.json', '.npmignore', 'README.md', 'LICENSE', 'CHANGELOG.md']
      .filter(file => fse.existsSync(path.join(pathRootDir, file)))
      .map(file =>
        fse.copyFile(
          path.join(pathRootDir, file),
          path.join(pathDistDir, file),
        ),
      ),
  );
const copyRelationalFilesWithSpinner = () =>
  withSpinner(copyRelationalFiles(pkgRoot, distDir), 'Copying package files');

async function prerelease() {
  try {
    await copyRelationalFilesWithSpinner();
  } catch (e) {
    console.error(chalk.red(e));
    process.exit(1);
  }
}

prerelease().catch(() => {});
