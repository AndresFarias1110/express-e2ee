// lib/app.ts
import express = require('express');
import { E2eEncryption } from './services/e2e-encryption/e2e-encryption';
import { E2EDecryption } from './services/e2e-decryption/e2ee-decryption';
// Create a new express application instance
const app: express.Application = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.get('/', function (req, res) {
  res.send('Hello World!!!!');
});
app.post('/encripted', (req, res) => {
    try {
        const e2eEncript = new E2eEncryption();
        const encripted = e2eEncript.doProcess(req.body);
        res.json(encripted);
    } catch (error) {
        res.json(error);
    }
});

app.post('/decripted', (req, res) => {
    try {
        const e2eDecry = new E2EDecryption();
        const decry = e2eDecry.doProcess(
            req.body.customerType,
            req.body.data,
            req.body.eventId,
            req.body.iv,
            req.body.ek,
            req.body.hk
        );
        res.json(decry);
    } catch (error) {
        res.json(error);
    }
})
app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});