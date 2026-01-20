import { createClient } from '@supabase/supabase-js';
import { env } from './env';

const supabaseUrl = process.env.SUPABASE_URL || 'https://exdmibuizlvhyczpqvio.supabase.co';
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || '';

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export default supabase;
