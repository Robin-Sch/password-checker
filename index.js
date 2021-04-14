const redactMode = true; // Redact passwords
const onlyShowUnsafe = true; // Only show unsafe or duplicated passwords
const writeToFile = false; // Write output to result.txt


const { green, red } = require('chalk');
const { readFile, writeFileSync } = require('fs');
const zxcvbn = require('zxcvbn');

readFile('bitwarden.json', 'utf8', (err, data) => {
    if (err) {
        return console.log('invalid file!')
    } else {
        return bitwarden(JSON.parse(data));
    }
});

const bitwarden = async (data) => {
    if(data.encrypted) return console.log('data is encrypted!');

    const passwords = {};
    for(let i = 0; i < data.items.length; i++) {
        let item = data.items[i];

        const exists = passwords[item.login.password];
        if (exists !== undefined) {
            passwords[item.login.password].amount += 1;
            passwords[item.login.password].services.push(item.name);
        }
        else passwords[item.login.password] = { amount: 1, services: [item.name] };

        if (i == data.items.length - 1) {
            return finish(passwords);
        }
    }
}

const finish = async (passwords) => {
    let string = '';
    const keys = Object.keys(passwords);
    const items = Object.values(passwords);

    for(let i = 0; i < items.length; i++) {
        const item = items[i];

        const zxcvn_result = zxcvbn(keys[i])

        const amount = item.amount;
        const password = redactMode ? 'REDACTED' : keys[i];
        const calcTime = zxcvn_result.crack_times_display.offline_slow_hashing_1e4_per_second;
        const services = item.services.join(' - ');
        const score = zxcvn_result.score;
        const feedback = zxcvn_result.feedback.warning + ' - ' + zxcvn_result.feedback.suggestions.join(' ,');

        let duplicated = false;
        if (amount > 1) duplicated = amount;

        let color = green;
        if (score !== 4 || duplicated) color = red;

        let message = `${password} | ${services}\n[${score}] ${calcTime} | ${feedback}\n`;
        if (duplicated) message += `This password is used ${duplicated} times!\n`;

        if (!onlyShowUnsafe || amount > 1) console.log(color(message));
        if (writeToFile) string += message + '\n';

        if (i == items.length - 1 && writeToFile) {
            return writeFileSync('result.txt', string);
        };
    }
}