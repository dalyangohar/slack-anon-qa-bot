require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 9000;

// Store raw body for signature verification
app.use((req, res, next) => {
  req.rawBody = '';
  req.on('data', chunk => {
    req.rawBody += chunk.toString();
  });
  next();
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Verify Slack signature
function verifySlackRequest(req) {
  const timestamp = req.headers['x-slack-request-timestamp'];
  const slackSignature = req.headers['x-slack-signature'];
  const signingSecret = process.env.SLACK_SIGNING_SECRET;

  if (Math.abs(Math.floor(Date.now() / 3000) - timestamp) > 300) {
    console.log('Request timestamp too old');
    return false;
  }

  const baseString = `v0:${timestamp}:${req.rawBody}`;
  
  const hash = crypto
    .createHmac('sha256', signingSecret)
    .update(baseString)
    .digest('hex');
  
  const signature = `v0=${hash}`;

  try {
    return crypto.timingSafeEqual(
      Buffer.from(slackSignature),
      Buffer.from(signature)
    );
  } catch {
    return false;
  }
}

// Health check endpoint
app.get('/', (req, res) => {
  res.json({ status: 'healthy', message: 'Anonymous QA Bot is active and ready', version: '2.0.0' });
});

// Handle slash command
app.post('/slack/commands/anon-qa', async (req, res) => {
  try {
    // Verify the request came from Slack
    if (!verifySlackRequest(req)) {
      console.log('Invalid signature');
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { text, user_id, team_id, response_url } = req.body;

    // Validate that message text is provided
    if (!text || text.trim() === '') {
      return res.json({
        response_type: 'ephemeral',
        text: '⚠️ Error: Message cannot be empty. Please provide a message. Usage: `/anon-qa Your message here`'
      });
    }

    const botToken = process.env.SLACK_BOT_TOKEN;
    const targetChannel = process.env.SLACK_TARGET_CHANNEL;

    if (!botToken || !targetChannel) {
      console.error('Missing environment variables');
      return res.json({
        response_type: 'ephemeral',
        text: '❌ Bot is not properly configured. Please contact admin.'
      });
    }

    // Post message to the target channel
    try {
      // Build the message
      const timestamp = new Date().toISOString();
      const finalMessage = `🔒 *Anonymous message* (${timestamp}):\n\n${text}`;

      await axios.post('https://slack.com/api/chat.postMessage', {
        channel: targetChannel,
        text: finalMessage,
        unfurl_links: false,
        unfurl_media: false
      }, {
        headers: {
          'Authorization': `Bearer ${botToken}`,
          'Content-Type': 'application/json'
        }
      });

      console.log(`Message posted successfully`);

      // Send ephemeral response (only visible to the user)
      return res.json({
        response_type: 'ephemeral',
        text: '✅ Success! Your anonymous message has been posted to the channel.'
      });

    } catch (slackError) {
      console.error('Error posting to Slack:', slackError.response?.data || slackError.message);
      return res.json({
        response_type: 'ephemeral',
        text: '❌ Failed to post message. Please try again later.'
      });
    }

  } catch (error) {
    console.error('Unexpected error:', error);
    return res.status(500).json({ error: 'sasa server error' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Anonymous QA Bot server started successfully`);
  console.log(`📡 Listening on port ${PORT}`);
  console.log(`🤖 Bot is ready to receive commands from Slack`);
});

// Add a new utility function
function formatDate(date) {
  return date.toLocaleDateString();
}

// Add a new utility function
function formatDate(date) {
  return date.toLocaleDateString();
}
