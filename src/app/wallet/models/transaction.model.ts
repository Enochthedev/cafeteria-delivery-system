import { Document, model, Model, Schema, SchemaTimestampsConfig, SchemaType, Types } from 'mongoose';
import { TransactionStatus, TransactionType } from '../types/wallet.type';

export interface ITransaction extends Document, SchemaTimestampsConfig {
    type: string;
    amount: number;
    currency: string;
    description: string;
    status: string;
}

const TransactionSchema: Schema<ITransaction> = new Schema<ITransaction>(
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
    {
        timestamps: true,
    },
);
