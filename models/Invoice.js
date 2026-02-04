const mongoose = require('mongoose');

const invoiceSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  invoiceNumber: { type: String, unique: true },
  planName: String,
  planSlug: String,
  billingCycle: { type: String, enum: ['monthly', 'yearly'], default: 'monthly' },
  subtotal: { type: Number, default: 0 },
  discount: { type: Number, default: 0 },
  tax: { type: Number, default: 0 },
  total: { type: Number, default: 0 },
  currency: { type: String, default: 'USD' },
  status: { type: String, enum: ['pending', 'paid', 'failed', 'cancelled', 'refunded', 'processing'], default: 'pending' },
  paymentMethod: { type: String, enum: ['stripe', 'jazzcash', 'easypaisa', 'bank_transfer', 'manual'] },
  stripePaymentIntentId: String,
  stripeInvoiceId: String,
  manualPayment: {
    transactionId: String,
    senderNumber: String,
    senderName: String,
    screenshotUrl: String,
    verifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    verifiedAt: Date,
    notes: String,
    rejectionReason: String
  },
  periodStart: Date,
  periodEnd: Date,
  pdfUrl: String
}, { timestamps: true });

invoiceSchema.pre('save', async function(next) {
  if (!this.invoiceNumber) {
    const year = new Date().getFullYear();
    const count = await mongoose.model('Invoice').countDocuments();
    this.invoiceNumber = `XMG-${year}-${String(count + 1).padStart(6, '0')}`;
  }
  next();
});

module.exports = mongoose.model('Invoice', invoiceSchema);
