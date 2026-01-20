import Mailgen from 'mailgen';
import nodemailer from 'nodemailer';

const sendMail = async (options) => {
  const mailGenerator = new Mailgen({
    theme: 'default',
    product: {
      name: 'Project Management App',
      link: 'https://yourapp.com',
    },
  });

  const emailText = mailGenerator.generatePlaintext(options.mailGenContent);
  const emailHTML = mailGenerator.generate(options.mailGenContent);

  const transporter = nodemailer.createTransport({
    host: process.env.MAILTRAP_SMTP_HOST,
    port: process.env.MAILTRAP_SMTP_PORT,
    auth: {
      user: process.env.MAILTRAP_USER,
      pass: process.env.MAILTRAP_PASS,
    },
  });

  const mailOptions = {
    from: '"Project Management App" <46ead8f9f894ff@sandbox.smtp.mailtrap.io>',
    to: options.email,
    subject: options.subject,
    text: emailText,
    html: emailHTML,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log('✅ Email sent successfully');
  } catch (error) {
    console.error('❌ Error sending email:', error);
  }
};


const emailVerificationMailgenContent = (username, verificationLink) => {
  return {
    body: {
      name: username,
      intro:
        "Welcome to Project Management App! We're excited to have you on board.",
      action: {
        instructions:
          'To get started with your account, please click the button below to verify your email address:',
        button: {
          color: '#2F4F4F', // Optional action button color
          text: 'Verify Your Email',
          link: verificationLink,
        },
      },
      outro:
        'If you did not sign up for this account, please ignore this email. If you have any questions, feel free to reply to this email.',
    },
  };
};

const forgotPasswordMailgenContent = (username, resetLink) => {
  return {
    body: {
      name: username,
      intro:
        'You have requested to reset your password. Please click the button below to proceed.',
      action: {
        instructions: 'Click the button below to reset your password:',
        button: {
          color: '#2F4F4F', // Optional action button color
          text: 'Reset Your Password',
          link: resetLink,
        },
      },
      outro:
        'If you did not request a password reset, please ignore this email. If you have any questions, feel free to reply to this email.',
    },
  };
};

export { forgotPasswordMailgenContent, emailVerificationMailgenContent, sendMail };
