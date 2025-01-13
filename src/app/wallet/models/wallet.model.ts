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
      default: 'NGN', // Default currency
      required: true,
    },
    transactions: {
      type: [
        {
          type: Schema.Types.ObjectId,
          ref: 'Transaction',
        },
      ],
      default: [],
    }
  },
  {
    timestamps: true,
  },
);

export const WalletModel: Model<IWalletDocument> = model<IWalletDocument>(
  'Wallet',
  WalletSchema,
);
