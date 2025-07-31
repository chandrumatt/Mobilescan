const fs = require('fs');
const path = require('path');
const { PrismaClient } = require('@prisma/client');
const { yaraScan } = require('../services/yaraEngine.js');
const regexScan = require('../services/regexEngine.js');
const mlScore = require('../services/mlEngine.js');
const { scanSqliteDBAdvanced } = require('../services/sqliteScanner');
const { runAleapp } = require('../services/aleappService');

const prisma = new PrismaClient();
const archiveExtensions = ['.zip', '.tar', '.tar.gz', '.tgz'];

exports.handleScan = async (req, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'No file uploaded' });

  const ext = path.extname(file.originalname).toLowerCase();
  const yara = await yaraScan(file.path);
  const regex = await regexScan(file.path);
  const ml = await mlScore(file.path);
  // const  aleappResult = await runAleapp(file.path,ext);

  let sqliteScanResult = null;
  let aleappResult = null;

  if (ext === '.db' || ext === '.sqlite') {
    sqliteScanResult = await scanSqliteDBAdvanced(file.path);
  }

  if (archiveExtensions.includes(ext)) {
    aleappResult = await runAleapp(file.path, ext);
  }

  const riskLevel = ml > 0.7 || yara.length > 0 ? 'HIGH' : 'LOW';

  const record = await prisma.scan.create({
    data: {
      filename: file.originalname,
      yaraMatches: JSON.stringify(yara),
      regexMatches: JSON.stringify(regex),
      mlScore: ml,
      sqliteScan: JSON.stringify(sqliteScanResult),
      aleappScan: JSON.stringify(aleappResult?.reports || []),
      reportUrl: aleappResult?.reportUrl || null, 
      riskLevel,
    },
  });
  console.log(record)
  res.json(record);
};
