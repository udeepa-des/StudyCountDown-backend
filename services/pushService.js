const webpush = require("web-push");

class PushService {
  constructor() {
    webpush.setVapidDetails(
      `mailto:${process.env.EMAIL_USER}`,
      process.env.VAPID_PUBLIC_KEY,
      process.env.VAPID_PRIVATE_KEY
    );
  }

  async sendPushNotification(subscription, payload) {
    try {
      await webpush.sendNotification(subscription, JSON.stringify(payload));
      return true;
    } catch (error) {
      console.error("Push notification error:", error);
      
      // Handle expired/invalid subscriptions
      if (error.statusCode === 410 || error.statusCode === 404) {
        return "expired";
      }
      return false;
    }
  }

  async sendStudyReminderPush(subscription, planDetails) {
    const payload = {
      title: `Study Reminder: ${planDetails.subject}`,
      body: `Time to study ${planDetails.topic} for ${planDetails.hours} hour(s)`,
      icon: "/icons/icon-192x192.png",
      data: {
        url: `/plans/${planDetails._id}`,
      },
    };

    return this.sendPushNotification(subscription, payload);
  }
}

module.exports = new PushService();