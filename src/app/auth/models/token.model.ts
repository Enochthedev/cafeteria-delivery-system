import { TokenType } from '../../../enums/enum';
import { Document, Model, model, Schema, SchemaTimestampsConfig, Types } from 'mongoose';
import { UserDocument } from '../../users/models/user.model';

type TokenDocument = Document & SchemaTimestampsConfig & {
  user: Types.ObjectId | UserDocument;
  token: string;
  type: TokenType;
  usedAt?: Date | null;
  validTill: Date;
}

const TokenSchema: Schema<TokenDocument> = new Schema<TokenDocument>({
  user: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  token: {
    type: String,
    required: true,
    unique: true,
  },
  type: {
    type: String,
    enum: Object.values(TokenType),
    required: true,
  },
  usedAt: {
    type: Date,
    default: null,
  },
  validTill: {
    type: Date,
    required: true,
  },
}, {
  timestamps: true,
});

const Token: Model<TokenDocument> = model<TokenDocument>('Token', TokenSchema);

export { Token, TokenDocument };