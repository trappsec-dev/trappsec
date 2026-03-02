import { Controller, Get, Post, Body, Headers, HttpCode } from '@nestjs/common';

@Controller()
export class AppController {

    @Post('auth/register')
    @HttpCode(200)
    register(@Body('email') email: string) {
        return { status: "registered", email: email };
    }

    @Get('api/v2/profile')
    getProfile(@Headers('x-user-id') userId: string) {
        return { name: userId, is_admin: false };
    }

    @Post('api/v2/profile')
    @HttpCode(200)
    updateProfile(@Headers('x-user-id') userId: string) {
        return { name: userId, status: "updated" };
    }

    @Get('api/v2/orders')
    getOrders() {
        return {
            orders: [
                { id: "ord-123", item: "Laptop", amount: 1200 },
                { id: "ord-124", item: "Mouse", amount: 45 }
            ]
        };
    }
}
