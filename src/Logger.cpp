#include <cstdarg>
#include <cstdio>
#include <string>

class Logger {
public:
    enum class Color {
        DEFAULT,
        RED,
        GREEN,
        YELLOW,
        BLUE,
        MAGENTA,
        CYAN,
        WHITE,
        GRAY
    };

    static void logf(Color color, const char* format, ...) {

        printf("%s", get_color_code(color));


        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);


        printf("%s", get_color_code(Color::DEFAULT));
        printf("\n");
    }

private:
    static const char* get_color_code(Color color) {
        switch (color) {
        case Color::RED:     return "\033[31m";
        case Color::GREEN:   return "\033[32m";
        case Color::YELLOW:  return "\033[33m";
        case Color::BLUE:    return "\033[34m";
        case Color::MAGENTA: return "\033[35m";
        case Color::CYAN:    return "\033[36m";
        case Color::WHITE:   return "\033[37m";
        case Color::GRAY:   return "\033[90m";
        default:             return "\033[0m";
        }
    }
};
