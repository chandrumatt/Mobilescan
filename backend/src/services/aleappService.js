const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const ALEAPP_PATH = path.resolve(__dirname, '../../ALEAPP/aleapp.py');
const outputBase = path.join(__dirname, '../../reports/aleapp');

function getInputType(inputPath) {
  const ext = inputPath.toLowerCase();
  if (ext === '.zip') return 'zip';
  if (ext === '.tar') return 'tar';
  if (ext === '.gz' || ext === '.tgz' || inputPath.endsWith('.tar.gz')) return 'gz';
  return 'fs';
}

function runAleapp(inputFolder, extension) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(inputFolder)) return reject(new Error('Input folder does not exist'));

    if (!fs.existsSync(outputBase)) fs.mkdirSync(outputBase, { recursive: true });

    const randomSuffix = crypto.randomBytes(3).toString('hex');
    const aleappOutputFolder = path.join(outputBase, `aleapp-${randomSuffix}`);
    fs.mkdirSync(aleappOutputFolder, { recursive: true });

    const inputType = getInputType(extension);
    const command = `python3 "${ALEAPP_PATH}" -i "${inputFolder}" -o "${aleappOutputFolder}" -t ${inputType}`;

    exec(command, { timeout: 10 * 60 * 1000 }, (error, stdout, stderr) => {
      if (error) {
        console.error('ALEAPP error stdout:', stdout);
        console.error('ALEAPP error stderr:', stderr);
        return reject(error);
      }

      // Find the ALEAPP_* folder inside aleappOutputFolder
      const subdirs = fs.readdirSync(aleappOutputFolder).filter(f => f.startsWith('ALEAPP_Reports'));
      if (subdirs.length === 0) return resolve({ reports: [], count: 0, reportUrl: null });

      const reportDir = path.join(aleappOutputFolder, subdirs[0]);

      console.log("subdirs:",subdirs)
      // Move contents up one level
      fs.readdirSync(reportDir).forEach(item => {
        fs.renameSync(
          path.join(reportDir, item),
          path.join(aleappOutputFolder, item)
        );
      });

      fs.rmSync(reportDir, { recursive: true, force: true }); 

      const reportUrl = `http://localhost:4000/reports/aleapp/${path.basename(aleappOutputFolder)}/${subdirs}/_HTML/index.html`;

      resolve({
        reports: [],
        count: 0,
        reportUrl,
      });
    });
  });
}

module.exports = { runAleapp };
