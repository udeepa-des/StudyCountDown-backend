const nodemailer = require("nodemailer");
const { compile } = require("handlebars");
const fs = require("fs");
const path = require("path");

class EmailService {
  constructor() {
    this.transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
      },
    });
  }

  async sendEmail(to, subject, templateName, context) {
    try {
      const templatePath = path.join(
        __dirname,
        `../../templates/emails/${templateName}.hbs`
      );
      const template = fs.readFileSync(templatePath, "utf8");
      const compiledTemplate = compile(template);

      const mailOptions = {
        to,
        from:
          process.env.EMAIL_FROM ||
          `MindStreamer <noreply@${process.env.EMAIL_USER.split("@")[1]}>`,
        subject,
        html: compiledTemplate(context),
      };

      await this.transporter.sendMail(mailOptions);
      return true;
    } catch (error) {
      console.error("Email sending error:", error);
      return false;
    }
  }

  async sendPasswordReset(email, resetCode) {
    return this.sendEmail(email, "Password Reset Code", "password-reset", {
      resetCode,
      expiration: "10 minutes",
    });
  }

  async sendWelcomeEmail(email, name) {
    return this.sendEmail(email, "Welcome to MindStreamer!", "welcome", {
      name,
    });
  }

  async sendStudyPlanReminder(email, name, planDetails) {
    return this.sendEmail(
      email,
      `Reminder: ${planDetails.subject} Study Session`,
      "study-reminder",
      {
        name,
        ...planDetails,
      }
    );
  }
}

module.exports = new EmailService();
