const express = require('express');
const router = express.Router();
const User = require('../../models/User');
const Invoice = require('../../models/Invoice');
const Plan = require('../../models/Plan');

router.post('/', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  if (!webhookSecret) {
    return res.status(400).json({ error: 'Webhook secret not configured' });
  }
  
  let event;
  
  try {
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: 'Invalid signature' });
  }
  
  try {
    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const { userId, planSlug } = session.metadata;
        
        const plan = await Plan.findOne({ slug: planSlug });
        if (plan && userId) {
          await User.findByIdAndUpdate(userId, {
            stripeCustomerId: session.customer,
            stripeSubscriptionId: session.subscription,
            'subscription.plan': planSlug,
            'subscription.status': 'active',
            'subscription.serverLimit': plan.limits.servers,
            'subscription.startDate': new Date()
          });
        }
        break;
      }
      
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        await User.findOneAndUpdate(
          { stripeSubscriptionId: subscription.id },
          {
            'subscription.status': 'cancelled',
            'subscription.plan': 'free',
            'subscription.serverLimit': 1
          }
        );
        break;
      }
      
      case 'invoice.paid': {
        const invoice = event.data.object;
        // Record invoice
        break;
      }
    }
    
    res.json({ received: true });
  } catch (err) {
    console.error('Webhook handler error:', err);
    res.status(500).json({ error: 'Webhook handler failed' });
  }
});

module.exports = router;
