const nodemailer = require('nodemailer');

const {
  MAILGUN_SANDBOX,
  MAILGUN_PASS,
} = process.env;

const transporter = nodemailer.createTransport({
  service: 'Mailgun',
  auth: {
    user: MAILGUN_SANDBOX,
    pass: MAILGUN_PASS,
  },
});

const buildMessage = (address, token) => {
  const message = {
    from: 'App template <mailgun@template.app>',
    to: address,
    subject: 'Testing mail sending',
  };
  message.html =
    `<h3>¡Hola!<br> Probando el mail sender.</h3>
    <p>Este es el token que deberías usar: ${token}<p>
    <p>Otro texto.</p>`;
  return message;
};

class Mailer {
  static async sendResetEmail(address, token) {
    const message = buildMessage(address, token);
    return transporter.sendMail(message);
  }
}

module.exports = Mailer;
