// utils/reminderUtils.js
// Server-side copy of the advance-notice calculation used by the frontend.
// Keep this in sync with client/src/utils/reminderUtils.js — same logic,
// duplicated because the server needs it independent of any browser tab.

function getAdvanceMs(reminder) {
  const amount = parseInt(reminder.advanceNotice, 10) || 0;
  const unit = reminder.advanceUnit || "hours";

  const multipliers = {
    minutes: 60 * 1000,
    hours: 60 * 60 * 1000,
    days: 24 * 60 * 60 * 1000,
  };

  return amount * (multipliers[unit] || multipliers.hours);
}

module.exports = { getAdvanceMs };
