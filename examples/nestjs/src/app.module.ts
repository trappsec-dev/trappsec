import { Module } from '@nestjs/common';
import { ServeStaticModule } from '@nestjs/serve-static';
import { AppController } from './app.controller';
import { join } from 'path';

const frontendPath = join(__dirname, '..', '..', 'lure-frontend');

@Module({
    imports: [
        ServeStaticModule.forRoot({
            rootPath: frontendPath,
        }),
    ],
    controllers: [AppController],
    providers: [],
})
export class AppModule { }
