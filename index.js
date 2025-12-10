require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const { OpenAI } = require('openai');

const app = express();
const PORT = process.env.PORT || 10000;

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

  if (Math.abs(Math.floor(Date.now() / 1000) - timestamp) > 300) {
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

app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Anonymous QA Bot is running' });
});

// Function to detect message language
function detectLanguage(text) {
  try {
    // Check for Cyrillic characters (Russian, Ukrainian, etc.)
    const cyrillicRegex = /[\u0400-\u04FF]/g;
    const cyrillicMatches = text.match(cyrillicRegex);
    
    // If more than 20% of characters are Cyrillic, consider it Russian
    if (cyrillicMatches && cyrillicMatches.length > text.length * 0.2) {
      return 'ru';
    }
    
    return 'en'; // Default to English
  } catch (error) {
    console.log('Language detection error:', error.message);
    return 'en'; // Default to English on error
  }
}

// Function to get AI commentary using OpenAI
async function getAICommentary(message) {
  try {
    const openaiApiKey = process.env.OPENAI_API_KEY;
    
    if (!openaiApiKey) {
      console.log('OpenAI API key not configured, skipping AI commentary');
      return null;
    }

    // Detect language
    const language = detectLanguage(message);
    console.log(`Detected language: ${language} for message: "${message.substring(0, 50)}..."`);
    
    // Set system prompt based on language
    let systemPrompt;
    let userPrompt;
    
    if (language === 'ru') {
      systemPrompt = 'Ты модератор QA команды. Напиши ОЧЕНь краткий комментарий (1-2 коротких предложения). Стиль: "Отличное наблюдение! Документация действительно необходима..." Без вступлений, без лишних слов. Просто оценка + суть.';
      userPrompt = `Комментарий:\n\n"${message}"`;
    } else {
      systemPrompt = 'You are a QA moderator. Write a SHORT commentary (1-2 short sentences). Style: "Great point! Documentation is truly essential..." No preamble, no fluff. Just validation + the core issue.';
      userPrompt = `Commentary:\n\n"${message}"`;
    }

    const client = new OpenAI({ apiKey: openaiApiKey });

    const response = await client.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        {
          role: 'system',
          content: systemPrompt
        },
        {
          role: 'user',
          content: userPrompt
        }
      ],
      max_tokens: 150,
      temperature: 0.7
    });

    return response.choices[0].message.content;
  } catch (error) {
    console.error('AI commentary error:', error.message);
    return null; // If AI fails, continue without commentary
  }
}

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
      // Get AI commentary (optional, if API key is configured)
      const aiCommentary = await getAICommentary(text);
      
      // Build the final message
      let finalMessage = `🔒 *Anonymous message:*\n\n${text}`;
      
      if (aiCommentary) {
        finalMessage += `\n\n---\n📊 *AI Commentary:*\n${aiCommentary}`;
      }

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

