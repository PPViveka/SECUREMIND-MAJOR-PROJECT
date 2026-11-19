const express = require('express');
const childProcess = require('child_process');
const app = express();

const sessionToken = "demo-token-1234567890";

app.get('/render', (req, res) => {
  const user = req.query.user;
  res.send('<h1>Hello ' + user + '</h1>');
});

app.get('/proxy', async (req, res) => {
  const response = await fetch(req.query.url);
  res.send(await response.text());
});

app.get('/run', (req, res) => {
  childProcess.exec(req.query.command, () => res.send('done'));
});

const csrfToken = Math.random().toString(36);
const target = {};
Object.assign(target, req.body);
