export interface ActionResponse<T = void> {
  success: boolean;
  message?: string;
  data?: T;
  error?: string;
}

export interface SessionUser {
  id: string;
  name: string | null;
  email: string | null;
  image: string | null;
  role: string;
}
