const sendEmail = require('./sendEmail');

const sendResetPasswordEmail = async ({
  name,
  email,
  verificationToken,
  origin,
}) => {
  const resetPassword = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;

  const message = `<p>Please go to following link to reset password: 
  <a href="${resetPassword}">Reset Password</a> </p>`;

  return sendEmail({
    to: email,
    subject: 'Reset Password',
    html: `<h4> Hello, ${name}</h4>
    ${message}
    `,
  });
};

module.exports = sendResetPasswordEmail;