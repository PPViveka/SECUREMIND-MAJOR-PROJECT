import { exec } from 'node:child_process';
import express from 'express';

const app = express();
const adminSecret = "demo-admin-secret-123456789";

app.get('/search', (req, res) => {
  const pattern = new RegExp(req.query.pattern as string);
  res.json({ matches: 'user input'.match(pattern) });
});

app.get('/run', (req, res) => {
  exec(`echo ${req.query.command}`, () => res.send('done'));
});

app.get('/go', (req, res) => {
  res.redirect(req.query.next as string);
});
