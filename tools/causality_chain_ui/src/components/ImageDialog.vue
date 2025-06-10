<template>
    <div>
        <el-button style="height: 25px; background-color: #34495e; color: white;"
            @click="callGuideVisiable = true; console.log($props.imagePath);">help</el-button>

        <div v-if="callGuideVisiable" class="modal-overlay">
            <div class="modal-content">
                <img :src="imagePath" alt="Image" class="modal-image" />
                <button class="close-button" @click="closeDialog">&#215;</button>
            </div>
        </div>
    </div>
</template>

<script>
export default {
    props: {
        imagePath: {
            type: String,
            required: true
        }
    },
    data() {
        return {
            callGuideVisiable: false,
        };
    },
    methods: {
        closeDialog() {
            this.callGuideVisiable = false;
        },
    },
};
</script>

<style scoped>
.modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.5);
    display: flex;
    justify-content: center;
    align-items: center;
    z-index: 1000;
}

.modal-content {
    position: relative;
    background-color: #333;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    max-width: 60%;
    max-height: 90%;
    overflow: auto;
}

.modal-image {
    width: 100%;
    height: auto;
    display: block;
}

.close-button {
    font-size: 20px;
    position: absolute;
    top: 10px;
    right: 10px;
    background-color: gray;
    color: white;
    border: none;
    border-radius: 2px;
    padding: 1px 5px;
    cursor: pointer;
    z-index: 10;
}
</style>