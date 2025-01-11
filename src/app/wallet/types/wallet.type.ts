import { Types, Document, SchemaTimestampsConfig } from 'mongoose';

export enum TransactionType {
  CREDIT = 'credit',
  DEBIT = 'debit',
}

export enum TransactionStatus {
  PENDING = 'pending',
  COMPLETED = 'completed',
  FAILED = 'failed',
}

export interface IWallet extends SchemaTimestampsConfig {
  user: Types.ObjectId;
  balance: number;
  currency: string;
  transactions: {
    type: TransactionType;
    amount: number;
    currency: string;
    description: string;
    status: TransactionStatus;
    createdAt: Date;
  }[];
}

export interface IWalletDocument extends IWallet, Document {}
