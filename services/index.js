const EmailService = require("./emailService");
const SMSService = require("./smsService");
const PushService = require("./pushService");

class NotificationService {
  constructor() {
    this.email = EmailService;
    this.sms = SMSService;
    this.push = PushService;
  }

  async sendUserNotification(user, notificationType, data) {
    const results = {
      email: false,
      sms: false,
      push: false,
    };

    // Email notifications
    if (user.emailNotifications && user.email) {
      switch (notificationType) {
        case "passwordReset":
          results.email = await this.email.sendPasswordReset(
            user.email,
            data.code
          );
          break;
        case "studyReminder":
          results.email = await this.email.sendStudyPlanReminder(
            user.email,
            user.name,
            data.planDetails
          );
          break;
        case "welcome":
          results.email = await this.email.sendWelcomeEmail(user.email, user.name);
          break;
      }
    }

    // SMS notifications
    if (user.mobileNotifications && user.phone) {
      switch (notificationType) {
        case "passwordReset":
          results.sms = await this.sms.sendPasswordResetSMS(user.phone, data.code);
          break;
        case "studyReminder":
          results.sms = await this.sms.sendStudyReminderSMS(
            user.phone,
            data.planDetails
          );
          break;
      }
    }

    // Push notifications
    if (user.pushSubscription) {
      switch (notificationType) {
        case "studyReminder":
          results.push = await this.push.sendStudyReminderPush(
            user.pushSubscription,
            data.planDetails
          );
          break;
      }
    }

    return results;
  }
}

module.exports = new NotificationService();