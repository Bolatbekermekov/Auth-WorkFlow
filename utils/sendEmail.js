const nodemailer = require('nodemailer');

const sendEmail = async ({ to, subject, html }) => {
  let testAccount = await nodemailer.createTestAccount();

  const transporter = nodemailer.createTransport({
    host: 'smtp.ethereal.email',
    port: 587,
    auth: {
      user: 'alverta.kertzmann39@ethereal.email      ',
      pass: 'vAz1mrJR8gCdXyqZrV',
    },
  });

  return transporter.sendMail({
    from: '"Bolatbek Ermekov" <ermekbolatbek21@gmail.com>', // sender address
    to,
    subject,
    html,
  });
};

module.exports = sendEmail;