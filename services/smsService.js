const twilio = require("twilio");

class SMSService {
  constructor() {
    this.client = twilio(
      process.env.TWILIO_ACCOUNT_SID,
      process.env.TWILIO_AUTH_TOKEN
    );
  }

  async sendSMS(to, body) {
    try {
      if (process.env.NODE_ENV === "test") return true;

      await this.client.messages.create({
        body,
        from: process.env.TWILIO_PHONE_NUMBER,
        to,
      });
      return true;
    } catch (error) {
      console.error("SMS sending error:", error);
      return false;
    }
  }

  async sendPasswordResetSMS(phone, resetCode) {
    const message = `Your MindStreamer password reset code is: ${resetCode}. It will expire in 10 minutes.`;
    return this.sendSMS(phone, message);
  }

  async sendStudyReminderSMS(phone, planDetails) {
    const message = `Reminder: ${planDetails.subject} study session today for ${planDetails.hours} hour(s). Topic: ${planDetails.topic}`;
    return this.sendSMS(phone, message);
  }
}

module.exports = new SMSService();
