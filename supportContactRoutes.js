export function escapeEmailHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[char]);
}

export function registerSupportContactRoute(app, deps) {
  const { transporter, limiter, from, to, logger = console } = deps;

  app.post('/api/support/contact', limiter, async (req, res) => {
    const fields = ['name', 'email', 'role', 'topic', 'message', 'project', 'website'];
    const values = Object.fromEntries(fields.map(field => [
      field,
      typeof req.body?.[field] === 'string' ? req.body[field].trim() : '',
    ]));
    const { name, email, role, topic, message, project, website } = values;

    if (website) return res.status(400).json({ error: 'Unable to send your message.' });
    if (!name || name.length > 100 || /[\r\n]/.test(name)) {
      return res.status(400).json({ error: 'Enter your name (up to 100 characters).' });
    }
    if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Enter a valid email address.' });
    }
    if (!topic || topic.length > 100 || /[\r\n]/.test(topic)) {
      return res.status(400).json({ error: 'Choose a support topic.' });
    }
    if (!message || message.length < 10 || message.length > 5000) {
      return res.status(400).json({ error: 'Describe your question or problem (10–5000 characters).' });
    }
    if (role.length > 80 || project.length > 120) {
      return res.status(400).json({ error: 'Role or project name is too long.' });
    }

    try {
      await transporter.sendMail({
        from,
        to,
        replyTo: { name, address: email },
        subject: `OneProjectApp support: ${topic}`,
        text: [
          `Name: ${name}`,
          `Email: ${email}`,
          `Role: ${role || 'Not provided'}`,
          `Project: ${project || 'Not provided'}`,
          `Topic: ${topic}`,
          '',
          message,
        ].join('\n'),
        html: `<p><strong>Name:</strong> ${escapeEmailHtml(name)}<br>
          <strong>Email:</strong> ${escapeEmailHtml(email)}<br>
          <strong>Role:</strong> ${escapeEmailHtml(role || 'Not provided')}<br>
          <strong>Project:</strong> ${escapeEmailHtml(project || 'Not provided')}<br>
          <strong>Topic:</strong> ${escapeEmailHtml(topic)}</p>
          <p>${escapeEmailHtml(message).replace(/\n/g, '<br>')}</p>`,
      });
      return res.json({ success: true, message: 'Your message has been sent to support.' });
    } catch (error) {
      logger.error('[POST /api/support/contact] Email delivery failed:', error);
      return res.status(502).json({ error: 'We could not send your message right now. Please try again later.' });
    }
  });
}
