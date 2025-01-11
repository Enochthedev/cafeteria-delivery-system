import {
  model,
  Model,
  Schema,
} from 'mongoose';
import {
  IWalletDocument,
  TransactionStatus,
  TransactionType,
} from '../types/wallet.type';

const WalletSchema: Schema<IWalletDocument> = new Schema<IWalletDocument>(
  {
    user: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    balance: {
      type: Number,
      default: 0,
      required: true,
    },
    currency: {
      type: String,
      default: 'USD', // Default currency
      required: true,
    },
    transactions: [
      {
        type: {
          type: String,
          enum: TransactionType,
          required: true,
        },
        amount: {
          type: Number,
          required: true,
        },
        currency: {
          type: String,
          required: true,
        },
        description: {
          type: String,
          required: true,
        },
        status: {
          type: String,
          enum: TransactionStatus,
          default: TransactionStatus.PENDING,
        },
      },
    ],
  },
  {
    timestamps: true,
  },
);

export const WalletModel: Model<IWalletDocument> = model<IWalletDocument>(
  'Wallet',
  WalletSchema,
);
