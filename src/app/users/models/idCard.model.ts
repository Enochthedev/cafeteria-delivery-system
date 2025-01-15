import { Document, model, Model, Schema, SchemaTimestampsConfig, SchemaType, Types } from 'mongoose';

export interface IdCard extends Document, SchemaTimestampsConfig {
    user: Types.ObjectId;
    front: string;
    back: string;
    verified: boolean;
    details: {
        name: string;
        matricNumber: string;
        department: string;
        level: number;
        campus: string;
    };
}

const IdCardSchema: Schema<IdCard> = new Schema<IdCard>(
        {
            user: {
                type: Schema.Types.ObjectId,
                ref: 'User',
                required: true,
            },
            front: {
                type: String,
                required: true,
            },
            back: {
                type: String,
                required: true,
            },
            verified: {
                type: Boolean,
                default: false,
            },
            details: {
                name: {
                    type: String,
                    required: true,
                },
                matricNumber: {
                    type: String,
                    required: true,
                },
                department: {
                    type: String,
                    required: true,
                },
                level: {
                    type: Number,
                    required: true,
                },
                campus: {
                    type: String,
                    required: true,
                },
            },
        },
        {
            timestamps: true,
        },
);


const IdCard: Model<IdCard> = model<IdCard>('IdCard', IdCardSchema);
