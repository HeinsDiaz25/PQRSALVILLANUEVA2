import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { verify } from "jsonwebtoken"

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key"

export function middleware(request: NextRequest) {
  // Verificar si la ruta es del área de administración (excepto la página de login y registro)
  if (
    request.nextUrl.pathname.startsWith("/admin") &&
    !request.nextUrl.pathname.startsWith("/admin/login") &&
    !request.nextUrl.pathname.startsWith("/admin/register") &&
    request.nextUrl.pathname !== "/admin"
  ) {
    // Obtener el token de la cookie
    const token = request.cookies.get("adminToken")?.value

    // Si no hay token, redirigir al login
    if (!token) {
      const loginUrl = new URL("/admin/login", request.url)
      return NextResponse.redirect(loginUrl)
    }

    try {
      // Verificar el token
      verify(token, JWT_SECRET)
      return NextResponse.next()
    } catch (error) {
      // Token inválido o expirado
      const loginUrl = new URL("/admin/login", request.url)
      return NextResponse.redirect(loginUrl)
    }
  }

  return NextResponse.next()
}

// Configurar las rutas que deben ser verificadas por el middleware
export const config = {
  matcher: ["/admin/:path*"],
}
