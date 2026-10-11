import {
    Controller, Get, Post, Body, Headers, HttpCode, Param, Req,
    CallHandler, ExecutionContext, Injectable, NestInterceptor, UseInterceptors,
} from '@nestjs/common';
import { AnyFilesInterceptor } from '@nestjs/platform-express';
import { Request } from 'express';

// Parses multipart bodies on the Express adapter (multer, route-level); on Fastify
// @fastify/multipart, registered in main.ts, has already attached the fields.
@Injectable()
class MultipartFields implements NestInterceptor {
    private readonly multer = new (AnyFilesInterceptor())();

    intercept(ctx: ExecutionContext, next: CallHandler) {
        const req = ctx.switchToHttp().getRequest();
        return req.raw ? next.handle() : this.multer.intercept(ctx, next);
    }
}

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

    @Get('api/v2/orders/:id')
    getOrderDetail(@Param('id') id: string) {
        return { id, item: "Laptop", amount: 1200, status: "shipped" };
    }

    @Get('api/v2/echo/query')
    echoQuery(@Req() req: Request) {
        return req.query;
    }

    @Post('api/v2/echo/body')
    @HttpCode(200)
    echoBody(@Body() body: any) {
        return body || {};
    }

    @Post('api/v2/echo/form')
    @HttpCode(200)
    echoForm(@Body() body: any) {
        return body || {};
    }

    @Post('api/v2/echo/multipart')
    @HttpCode(200)
    @UseInterceptors(MultipartFields)
    echoMultipart(@Body() body: any) {
        return { ...(body || {}) };
    }
}
