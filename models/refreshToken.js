import mongoose from 'mongoose';

const refreshTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User',
  },
  token: {
    type: String,
    required: true,
  },
  expiryDate: {
    type: Date,
    required: true,
  }
}, { timestamps: true });

export default mongoose.model('RefreshToken', refreshTokenSchema);