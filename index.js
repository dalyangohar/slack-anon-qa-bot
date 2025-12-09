require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Store raw body for signature verification
app.use((req, res, next) => {
  let rawBody = '';
  req.on('data', chunk => {
    rawBody += chunk.toString();
  });
  req.on('end', () => {
    req.rawBody = rawBody;
    next();
  });
});

// Verify Slack signature
function verifySlackRequest(req) {
  const timestamp = req.headers['x-slack-request-timestamp'];
  const slackSignature = req.headers['x-slack-signature'];
  const signingSecret = process.env.SLACK_SIGNING_SECRET;

  // Check if request is not too old (Slack requirement: within 5 minutes)
  if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > 300) {
    console.log('Request timestamp too old');
    return false;
  }

  // Create the base string: v0:timestamp:body
  const baseString = `v0:${timestamp}:${req.rawBody}`;
  
  // Create HMAC SHA256 signature
  const hash = crypto
    .createHmac('sha256', signingSecret)
    .update(baseString)
    .digest('hex');
  
  const signature = `v0=${hash}`;

  // Compare signatures using constant-time comparison
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
  res.json({ status: 'ok', message: 'Anonymous QA Bot is running' });
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
        text: '❌ Please provide a message. Usage: `/anon-qa Your message here`'
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
      await axios.post('https://slack.com/api/chat.postMessage', {
        channel: targetChannel,
        text: `Anonymous message:\n\n${text}`,
        unfurl_links: false,
        unfurl_media: false
      }, {
        headers: {
          'Authorization': `Bearer ${botToken}`,
          'Content-Type': 'application/json'
        }
      });

      console.log(`Message posted successfully from user ${user_id}`);

      // Send ephemeral response (only visible to the user)
      return res.json({
        response_type: 'ephemeral',
        text: '✅ Your message has been sent anonymously.'
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
    return res.status(500).json({ error: 'Internal server error' });
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
  console.log(`🚀 Anonymous QA Bot running on port ${PORT}`);
  console.log(`Bot is ready to receive commands from Slack`);
});

